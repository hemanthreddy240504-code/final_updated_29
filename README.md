# EtiDhi Pipeline Intelligence

FastAPI + SQLAlchemy pipeline tracker with secure account recovery.

## Authentication
- Register: creates a unique User ID such as `ETD-000001`.
- Login: email **or User ID** + password.
- Forgot password: creates a one-time, 30-minute reset token and emails a reset link.
- Forgot User ID: emails the registered User ID.
- Change password: authenticated users can change their password from the dashboard.
- Passwords are stored as PBKDF2-SHA256 hashes, never plaintext.
- Reset tokens are stored as SHA-256 hashes and are single-use.

## Production email setup on Render
Set these environment variables:
- `APP_BASE_URL` = your deployed Render URL, for example `https://etidhi-pipeline-tracker.onrender.com`
- `SMTP_HOST`
- `SMTP_PORT` (usually `587`)
- `SMTP_USERNAME`
- `SMTP_PASSWORD` (use a provider app password, not your normal mailbox password)
- `SMTP_FROM`
- `SMTP_USE_TLS=true`

For Gmail/Google Workspace, enable 2-Step Verification and use an App Password for `SMTP_PASSWORD`.

If SMTP variables are missing during local development, the API prints the generated recovery link/User ID in the server logs and the browser displays a development-only recovery result. Configure SMTP before production.

## Run locally
```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `/auth`.

## Existing database
The application automatically adds the `user_id` column to the existing SQLite database and assigns IDs to existing users. Existing companies and passwords are preserved.

## Administrator access

Set `ADMIN_EMAIL` and `ADMIN_PASSWORD` in `.env` for local development or as Render environment variables in production. On startup, the application creates that account as an administrator if it does not exist, or restores its admin role if it already exists.

Administrators can open the **Admin panel** from the dashboard to view users, promote/demote accounts, and delete accounts. The API also protects admin operations server-side; hiding the UI is not the security boundary.
