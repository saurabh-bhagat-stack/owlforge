---
name: Django
applies_to: django
description: Django-specific weak spots.
---
## Signals
`csrftoken`/`sessionid` cookies, `/admin/`, `__debug__`, `DisallowedHost`, Django error pages.

## Focus
- `DEBUG=True` error pages leak settings, SQL, stack traces, SECRET_KEY → check for a verbose
  500.
- `/admin/` exposure and weak creds; default apps.
- SSTI is rare (autoescape on) but check `|safe`/`mark_safe` sinks and format-string views.
- Mass assignment via ModelForm `fields='__all__'`; IDOR on PK-based detail views.
- Open redirect via `next=` on login. Pickle/session deserialization if a custom serializer.
