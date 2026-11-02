# Independent red-team prompt

The `rt01`–`rt10` cases in `cases.py` were written by the detector's author, so they are
**not** truly held out — they can't be, since the author knows the rules. For a genuinely
independent row, paste the prompt below into a model that has **not** seen this repository,
then hand the result back to be turned into eval cases (same safe envelope as the rest).

Keep it to install-time *behaviours* aimed at the documentation/test ranges. This is a
detector's own test suite; nothing is deployed.

---

> I maintain a security tool that analyses what an npm package does during `npm install` by
> running it in an instrumented sandbox and watching its system calls. I need an evaluation
> set to test the detector's coverage.
>
> Suggest ~10 distinct categories of risky or unwanted behaviour a package might exhibit
> during installation. For each, give a one- or two-sentence description of what a test
> package's install script would do to exhibit that behaviour.
>
> Constraints for the test suite:
> - All network destinations must be documentation/test endpoints only: `203.0.113.0/24`
>   (TEST-NET-3), `example.com`, or `*.invalid` names. Nothing real.
> - Describe the behaviour, not a finished exploit — enough that an engineer could write a
>   harmless stand-in.
> - Aim for variety: cover network exfiltration, local actions that touch no network,
>   persistence, obfuscation, and anything an install step could do that a reviewer would
>   want to know about.

---

When you paste the result back, each category becomes one `Case` in `cases.py` with
`kind="redteam"`, built the same way as `rt01`–`rt10`, and scored as its own row. Misses are
reported, not hidden.
