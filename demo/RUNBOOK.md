# Chamber recovery runbook

Symptom: checks finish as "Could not verify", or the health history shows `ok: false`.
Check it: Modal Dict `pr-detonator-health` (`latest`, `history`; written every 10 min by
`chamber_health`), or `ssh ubuntu@3.223.99.234 'curl -s --cacert /etc/pr-detonator/tls/cert.pem https://127.0.0.1:8443/health'`.

1. **Restart the services** (fixes most problems, ~30 s):
   `sudo systemctl restart tetragon detonator-egress detonator-dns chamber`, then check health.
2. **Re-provision in place** (~3 min): copy `shared/` and `chamber/` to the VM and run
   `sudo bash chamber/provision/setup.sh`. Idempotent; keeps the secret and the TLS cert.
3. **Replace the VM from the AMI** (`pr-detonator-chamber-2026-11-01`): launch it in the same
   subnet and security group (port 8443 open, SSH from your IP), no IAM role, IMDSv2 required
   with hop limit 1. **Re-associate the Elastic IP 3.223.99.234** to the new instance. The
   cert, the secret and the Modal `chamber` secret then stay valid; nothing changes in the Brain.
4. **Only if the IP changed:** on the VM, `sudo rm -rf /etc/pr-detonator/tls` and re-run
   `setup.sh` (it makes a cert for the new IP). Then recreate the Modal `chamber` secret with the
   new `CHAMBER_URL`, the same `CHAMBER_SECRET` (from `/etc/pr-detonator/env`, never echoed) and
   `CHAMBER_CA_PEM` (`/etc/pr-detonator/tls/cert.pem`), and redeploy the Brain.
5. **Verify:** push an empty commit to `e1-readme-typo` (expect ✅) and `e4-typo-exfil`
   (expect 🛑); run `chamber_health` once (`modal.Function.from_name("pr-detonator",
   "chamber_health").remote()`).

Recovery time from the AMI has not been measured yet (fresh-VM test pending).
