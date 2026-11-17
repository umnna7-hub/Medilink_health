GRANT SELECT, INSERT, UPDATE ON medilink_health.user_invites
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE ON medilink_health.invite_rate_limits
    TO 'medilink_app'@'localhost';
GRANT SELECT, INSERT, UPDATE, DELETE ON medilink_health.mfa_recovery_codes
    TO 'medilink_app'@'localhost';
