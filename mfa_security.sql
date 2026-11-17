ALTER TABLE users
    MODIFY mfa_secret VARCHAR(255) NULL;

ALTER TABLE users
    ADD COLUMN mfa_confirmed_at DATETIME NULL;

ALTER TABLE users
    ADD COLUMN mfa_secret_format
        ENUM('legacy', 'fernet') NOT NULL DEFAULT 'legacy';

ALTER TABLE users
    ADD COLUMN session_version INT UNSIGNED NOT NULL DEFAULT 0;

UPDATE users
SET mfa_secret_format = 'fernet'
WHERE mfa_secret IS NULL
  AND mfa_secret_format = 'legacy';

ALTER TABLE users
    MODIFY mfa_secret_format
        ENUM('legacy', 'fernet') NOT NULL DEFAULT 'fernet';

CREATE TABLE IF NOT EXISTS mfa_recovery_codes (
    recovery_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    code_hash CHAR(64) NOT NULL,
    used_at DATETIME NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (recovery_id),
    KEY idx_mfa_recovery_user_unused (user_id, used_at),
    CONSTRAINT fk_mfa_recovery_user
        FOREIGN KEY (user_id) REFERENCES users (user_id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
