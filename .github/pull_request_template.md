## Challenge

- Path: `challenges/<category>/<slug>/`
- Mode: static / shared / per-team
- Difficulty:

CI runs `tools/ctf.py check`, `dist --verify`, and `test` on the changed challenges. The items below still need a person.

## Review checklist

- [ ] Idea, category, and difficulty agreed with organizers.
- [ ] CI is green, or the failing job is explained below (e.g. pwn waiting for a jail runner).
- [ ] `dist/` inspected by hand, including archive contents and file metadata.
- [ ] Writeup explains the intended path; steps are discoverable from the description and handout.
- [ ] Limits, jail/non-root setup, and outbound network needs reviewed.
- [ ] Pwn: tested on native Linux amd64; `checksec` recorded in the README.
- [ ] Per-team: two-instance, reset, and expiry tests done ([Architecture §6](../docs/ARCHITECTURE.md#6-per-team-instances)).
- [ ] Independent test-solver: @___ — platform and commands: ___ — result: ___
- [ ] Extra infra requirements and exceptions documented and approved.

## Notes
