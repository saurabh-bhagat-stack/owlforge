---
name: OS command injection / RCE
applies_to: rce
description: Command injection and code execution — read-only proof only.
---
## Where to look
Params feeding shell/exec: ping/host/dns tools, file conversion, archive, `cmd=`,`exec=`,
filename handling, and template/eval endpoints.

## Techniques
- Command separators: `;`,`|`,`&&`,`` `cmd` ``,`$(cmd)`,`%0a`. Confirm with a benign command.
- Blind: time-based (`sleep 5`) or OOB (`curl http://oob/`) when no output is reflected.
- Argument injection: a leading `-`/`--flag` that changes a tool's behaviour.

## Validation signal
Deterministic command output (`id` → `uid=`/`gid=`, `hostname`) OR a measured delay / OOB hit.
PROOF MUST BE READ-ONLY: `id`, `hostname`, `uname` — never write, delete, or spawn shells.

## Example payloads
`1;id` · `1|id` · `$(id)` · `1&&id` · `` `id` `` · `1; sleep 5`
