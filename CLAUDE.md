# DNS Panel Project Rules

## Version Numbering

Version releases are created automatically by GitHub Actions on every push to `main`.

- The first automated release created by the workflow is `v0.02`
- Subsequent releases automatically increment the last numeric segment of the latest `v*` tag
- `backend/app.py` keeps a fallback `APP_VERSION` for local or offline use only; it is not meant to be manually incremented on every code change
- The backend exposes `GET /api/version` (no auth required)
- The frontend `SettingsPage.vue` reads from this endpoint dynamically
