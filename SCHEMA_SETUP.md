# Database schema setup

The database configured by `DB_NAME` in `backend/.env` must exist before
running these steps. Use a MySQL administrator account for schema creation and
the app-user script.

Before applying migrations, copy `backend/.env.example` to `backend/.env` and
set the database connection, `JWT_SECRET_KEY`, and `MFA_ENCRYPTION_KEY`. The
MFA key must be available to the migration runner if it finds existing
unencrypted MFA secrets.

Run the following in order:

1. Apply the exported base schema from the project root:

   ```powershell
   cmd /c "mysql -u root -p medilink_health < schema.sql"
   ```

   Replace `medilink_health` if `DB_NAME` uses a different database name.
   Enter the MySQL administrator password at the prompt.

2. From the `backend/` directory, apply the project migrations in order:

   ```powershell
   .\venv\Scripts\python.exe ..\apply_migrations.py
   ```

   The runner uses `backend/database.py` and `backend/.env`. It applies
   `payments.sql`, `patient_dashboard.sql`, `login_attempts.sql`,
   `mfa_setup.sql`, `user_invites.sql`, then `mfa_security.sql`. It skips
   statements that report a duplicate MySQL table, column, index, or foreign-key
   name; other errors stop the run. The MFA security migration encrypts legacy
   authenticator secrets with Fernet and requires staff to confirm MFA at their
   next sign-in.

3. Apply the restricted application-user grants from the project root:

   ```powershell
   cmd /c "mysql -u root -p < create_app_user.sql"
   ```

   Review `create_app_user.sql` and replace its placeholder password through
   an approved secret-handling process before running it. Do not commit real
   credentials.

   For an existing installation with `medilink_app` already created, do not
   rerun the `CREATE USER` script. Instead, apply the additional table grants
   as a MySQL administrator:

   ```powershell
   cmd /c "mysql -u root -p < onboarding_grants.sql"
   ```

4. Configure `MFA_ENCRYPTION_KEY` in `backend/.env`, then, from the `backend/`
   directory, create the first administrator:

   ```powershell
   .\venv\Scripts\python.exe create_admin.py
   ```

   The command prompts for the administrator details, refuses to create a
   duplicate email or a second administrator, and writes an audit event. The
   administrator must complete MFA enrollment at first sign-in.

After migrations, re-export the schema from the `backend/` directory:

```powershell
.\venv\Scripts\python.exe export_schema.py
Select-String -Path ..\schema.sql -Pattern 'login_attempts|mfa_secret'
```

The export should contain the `login_attempts` table definition and the
`mfa_secret`, `mfa_confirmed_at`, `user_invites`, and
`mfa_recovery_codes` definitions.

Generate the MFA key with:

```powershell
.\venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Keep the generated key private and backed up securely. Do not put it in the
frontend environment or commit it.
