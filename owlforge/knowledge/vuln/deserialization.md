---
name: Insecure deserialization
applies_to: deserialization
description: Untrusted serialized objects deserialized into code/behaviour change.
---
## Where to look
Cookies/params/bodies holding serialized blobs: Java (`rO0AB...` base64, `application/
x-java-serialized-object`), PHP (`O:8:"...":` in cookies/params), .NET (`__VIEWSTATE`,
BinaryFormatter), Python pickle, Ruby Marshal, Node (node-serialize `_$$ND_FUNC$$_`).

## Techniques
- Fingerprint the format from the blob's magic (base64 `rO0` = Java, `O:`/`a:` = PHP,
  `gASV` = pickle). Decode and inspect class names.
- Tamper-detect: flip a byte / change a field and see if the server errors with a
  deserialization stack trace (confirms it deserializes attacker input).
- Gadget chains are framework-specific (ysoserial for Java, PHP POP chains). Prove impact
  OUT-OF-BAND and READ-ONLY: a gadget that triggers a DNS/HTTP callback to your collaborator
  (URLDNS for Java) confirms deserialization without running destructive commands.

## Validation signal
A deserialization-specific error on tampering, or an out-of-band callback from a benign
gadget (e.g. Java URLDNS) — not a destructive command.
