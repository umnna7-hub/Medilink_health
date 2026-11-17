# Database schema setup

The database configured by `DB_NAME` in `backend/.env` must exist before
running these steps. Use a MySQL administrator account for schema creation and
the app-user script.

Run the following in order:

1. Apply the exported base schema from the project root:

   ```powershell
   cmd /c "mysql -u root -p medilink_health < schema.sql"
   ```

   Replace `medilink_health` if `DB_NAME` uses a different database name.
   Enter the MySQL administrator password at the prompt.

2. From the `backend/` directory, apply the project migrations in order:

   ```powershell
   python ..\apply_migrations.py
   ```

   The runner uses `backend/database.py` and `backend/.env`. It applies
   `payments.sql`, `patient_dashboard.sql`, `login_attempts.sql`, then
   `mfa_setup.sql`. It skips statements that report a duplicate MySQL table,
   column, index, or foreign-key name; other errors stop the run.

3. Apply the restricted application-user grants from the project root:

   ```powershell
   cmd /c "mysql -u root -p < create_app_user.sql"
   ```

   Review `create_app_user.sql` and replace its placeholder password through
   an approved secret-handling process before running it. Do not commit real
   credentials.

After migrations, re-export the schema from the `backend/` directory:

```powershell
python export_schema.py
Select-String -Path ..\schema.sql -Pattern 'login_attempts|mfa_secret'
```

The export should contain the `login_attempts` table definition and the
`mfa_secret` column in `users`.
