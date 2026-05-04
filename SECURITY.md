# Security Policy

## Reporting issues with this harness

If you find a vulnerability in `purple-scaffold` itself (the
orchestrator, state machine, guards, lab target, or any code in this
repo), please email **euanmcrosson@gmail.com** rather than opening a
public issue.

Expected response:
- Acknowledgement within 7 days.
- Initial assessment (in scope / out of scope, severity) within 14 days.
- Fix or mitigation within 30 days for confirmed valid reports.
- Disclosure coordinated with the reporter; default 90-day public
  disclosure window.

## Reporting findings *produced by* this harness against a third party

The `findings/` directory contains defensive-research artifacts about
external systems (frontier models, MCP servers, agent products). These
are **not** vulnerabilities in this repo — they're disclosures whose
target is the system named in each finding's title.

If you want to use this harness to produce your own findings:

1. **Stay inside scope.** Run probes only against systems whose
   security policies permit independent testing (open-source projects,
   bug-bounty programs you've signed up for, your own deployments).
2. **No live exfiltration.** The lab target in `lab/vulnerable_agent.py`
   logs `would_have_sent_email` rather than actually sending — keep
   that pattern when adapting to other targets. Probes should
   demonstrate the failure, not exploit it.
3. **Coordinate disclosure.** When you find something against a third
   party, follow that party's published security policy
   (`SECURITY.md`, bounty program rules, named contact). Default to a
   90-day window unless the target's policy specifies otherwise.
4. **The card format in `findings/` is the recommended structure.**
   Reproducer + control case + verbatim output + suggested mitigations
   + explicit "what is/isn't novel" section.

## Out of scope for this repo

- Bugs in the LLMs the harness probes (report to the model provider).
- Bugs in `garak`, MCP servers, or other external tooling (report
  upstream; the harness simply uses them).
- Issues in third-party products the harness has been pointed at —
  report to that product's security contact, citing the relevant card
  in `findings/` as evidence.
