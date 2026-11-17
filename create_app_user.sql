CREATE USER 'medilink_app'@'localhost'
    IDENTIFIED BY 'REPLACE_WITH_A_STRONG_PASSWORD';

GRANT SELECT, INSERT, UPDATE ON medilink_health.appointments
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.doctors
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.diagnostic_labs
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.hospitals
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.login_attempts
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.invite_rate_limits
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.lab_reports
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.medical_records
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.payments
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.revoked_tokens
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.users
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.user_invites
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON medilink_health.mfa_recovery_codes
    TO 'medilink_app'@'localhost';

GRANT SELECT, INSERT ON medilink_health.audit_logs
    TO 'medilink_app'@'localhost';
