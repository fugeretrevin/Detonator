# Chamber recovery runbook

**For when the Chamber VM is lost, broken, or has to move.** Written 2026-11-02 against the
live instance. One EC2 box runs everything, so this is the difference between a bad hour and a
lost submission.

> **Read this first — the one thing that will catch you out.** The Chamber's TLS certificate has
> the instance's **IP address baked in as a Subject Alternative Name**
> (`IP Address:3.223.99.234, IP Address:127.0.0.1`), and the Brain *pins* that certificate via
> `CHAMBER_CA_PEM`. If you restore onto a **different IP, TLS verification fails and every check
> becomes "Could not verify"** — correctly, but the demo is gone. So either bring the old IP
> with you, or regenerate the cert and update the Modal secret. Step 4 covers both.

## What the machine is

| | |
|---|---|
| OS / kernel | Ubuntu 26.04.1 LTS, `7.0.0-1014-aws` |
| Address | `3.223.99.234`, SSH as `ubuntu` (`~/.ssh/config` host `chamber`) |
| Code | `/opt/pr-detonator/{chamber,shared,venv}` |
| Config | `/etc/pr-detonator/env` (holds `CHAMBER_SECRET`, mode `600`) |
| TLS | `/etc/pr-detonator/tls/{cert,key}.pem` — cert valid to **2027-11-01** |
| DNS / egress config | `/etc/pr-detonator/{dnsmasq.conf,sinkhole.conf}` |
| Sandbox image | `detonator-sandbox:latest` (~491 MB), built from `chamber/sandbox/Dockerfile` |
| Services (all enabled) | `chamber.service` (uvicorn, port **8443**, runs as root), `tetragon.service`, `detonator-dns.service`, `detonator-egress.service` |
| Deliberately absent | **no IAM instance role** — the VM cannot reach AWS APIs, by design |

`chamber.service` runs:
`/opt/pr-detonator/venv/bin/uvicorn chamber.server:app --host 0.0.0.0 --port 8443 --no-access-log --ssl-keyfile /etc/pr-detonator/tls/key.pem --ssl-certfile /etc/pr-detonator/tls/cert.pem`

## 0. Before you need it: take the snapshot

**Not yet done — this requires AWS console access and is the one prerequisite this runbook
can't create for itself.** In the EC2 console: select the instance → *Actions → Image and
templates → Create image*. Name it `pr-detonator-chamber-<date>`. Leave "no reboot" unchecked if
you can afford the restart (a quiesced image is more trustworthy), and take it while no
detonation is running.

**Answered, Nov 3, 2026: `3.223.99.234` is an Elastic IP** (owner-confirmed). So a stop/start
does **not** change the address, and the pinned certificate keeps verifying across a reboot.
Recovery does not need a new cert or a Modal secret update — it needs the EIP **reassociated** to
whatever instance you bring up. Step 4's certificate-regeneration path is the fallback for
losing the EIP itself, not the normal case.

The snapshot above is still not taken, and that is now the whole of the exposure: the Elastic IP
guarantees the address will be right once something is running at it, not that there is anything
to launch.

## 1. Triage: is the box actually gone?

```bash
ssh chamber "systemctl is-active chamber.service tetragon.service detonator-dns.service detonator-egress.service"
curl -sk --max-time 10 https://3.223.99.234:8443/health
```

Healthy looks like `{"tetragon":true,"docker":true,"dns":true,"disk_free_gb":...,"busy":false}`.

- **SSH works, a service is down** → go to step 2. Don't rebuild.
- **SSH works, health shows `tetragon:false`** → step 2, restart Tetragon. Note that a blind
  collector now *fails closed*, so checks will say "Could not verify" until it is back.
- **SSH dead / instance terminated** → step 3.

## 2. Service-level recovery (minutes)

```bash
ssh chamber "sudo systemctl restart tetragon.service detonator-egress.service detonator-dns.service chamber.service"
sleep 5
ssh chamber "systemctl is-active chamber.service; curl -sk --max-time 10 https://127.0.0.1:8443/health"
```

If the Chamber answers but detonations fail, the code may be mid-deploy. Restore the last
backup (the deploy script makes one every time):

```bash
ssh chamber "cat /opt/pr-detonator/LAST_BACKUP"      # e.g. 20261102-214138
ssh chamber "sudo cp -a /opt/pr-detonator/backup-<stamp>/{chamber,shared} /opt/pr-detonator/ \
             && sudo systemctl restart chamber.service"
```

Disk full is the other common cause — `docker system prune -af` reclaims sandbox layers.

## 3. Rebuild from the AMI

1. Launch an instance from the snapshot, same type and security group (inbound **8443** from
   Modal, **22** from you).
2. **Attach the old Elastic IP** if you have one. This is the happy path: nothing else changes,
   because the cert still matches.
3. `ssh ubuntu@<ip>` and run step 2's restart, then the health check.

If you have no snapshot, rebuild from the repo: `chamber/provision/setup.sh`,
`install_tetragon.sh`, `iptables.sh`, then rebuild the sandbox image from
`chamber/sandbox/Dockerfile` and recreate `/etc/pr-detonator/env` with a fresh
`CHAMBER_SECRET` — which must then match the `chamber` Modal secret (step 4).

## 4. If the IP changed — fix TLS, or nothing will work

The Brain pins the cert, and the cert names the old IP. Two options:

**(a) Regenerate the cert for the new IP** (preferred), then re-pin:

```bash
# on the VM, with NEWIP set
ssh chamber
sudo openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 365 \
  -subj "/CN=pr-detonator-chamber" \
  -addext "subjectAltName=IP:$NEWIP,IP:127.0.0.1" \
  -keyout /etc/pr-detonator/tls/key.pem -out /etc/pr-detonator/tls/cert.pem
sudo chmod 600 /etc/pr-detonator/tls/key.pem
sudo systemctl restart chamber.service
```

Then update **both** values in the `chamber` Modal secret — `CHAMBER_URL` to the new address and
`CHAMBER_CA_PEM` to the new `cert.pem` — and redeploy the Brain:

```powershell
.venv\Scripts\python scripts\modal_cli.py deploy -m brain.app
```

**(b) Move the old Elastic IP to the new instance** and change nothing else. Faster when
available.

Either way `CHAMBER_SECRET` in `/etc/pr-detonator/env` must equal the one in the `chamber` Modal
secret, or every request fails HMAC verification and the check fails closed.

## 5. Acceptance — do not declare victory before this passes

```powershell
# 1. Brain can reach it and the signature round-trip works
.venv\Scripts\python scripts\modal_cli.py run <a scratch script calling chamber_health>
# 2. a real detonation, and the sensor witness must come back true
#    (run_chamber.py on the VM with a one-case manifest, then check:)
#      sensor == {"pre_seen": true, "post_seen": true}
# 3. end to end: push an empty commit to e2-add-lodash and confirm the check goes green
```

**All three, in order.** (1) proves transport and HMAC, (2) proves Tetragon is armed and
attributing — a restored box with a broken collector would otherwise look fine until every PR
turned "Could not verify" — and (3) proves the whole path. Write down the wall-clock time the
recovery took.

## 6. Clean up

Terminate any drill instance. Two Chambers answering on the same secret means a job can land on
the wrong one, and an idle instance costs money for nothing.

## Known limits of this runbook

- **Untested.** Written from the live configuration, not yet rehearsed against a restored
  instance. Step 3 and step 4(a) in particular are reasoned, not proven. Drill it before you
  rely on it (`docs/WEAKPOINTS.md` W6).
- One VM, one job at a time: recovery restores capacity, it does not add redundancy.
- The Tetragon version is whatever the snapshot holds; a from-scratch rebuild gets whatever
  `install_tetragon.sh` pins, which may differ from what the eval was measured on.
