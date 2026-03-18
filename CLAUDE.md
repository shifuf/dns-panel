# DNS Panel Project Rules

## Version Numbering (MANDATORY)

Every code update MUST increment the version number in `backend/app.py`:

```python
APP_VERSION = "0.1"  # <-- increment this on every change
```

- Version starts from `0.1`
- Minor changes: increment patch (e.g., `0.1` -> `0.2`)
- Feature additions: increment minor (e.g., `0.9` -> `1.0`)
- The backend exposes `GET /api/version` (no auth required) returning `{"version": "X.Y"}`
- The frontend `SettingsPage.vue` reads from this endpoint dynamically
- This rule applies regardless of which IDE, AI tool, or developer makes the change
