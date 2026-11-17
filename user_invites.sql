ALTER TABLE users
    MODIFY account_status
        ENUM('pending', 'active', 'suspended', 'deactivated')
        NOT NULL DEFAULT 'active';

CREATE TABLE IF NOT EXISTS user_invites (
    invite_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    user_id INT NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    used_at DATETIME NULL,
    created_by INT NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (invite_id),
    UNIQUE KEY uq_user_invites_token_hash (token_hash),
    KEY idx_user_invites_user_expiry (user_id, expires_at),
    CONSTRAINT fk_user_invites_user
        FOREIGN KEY (user_id) REFERENCES users (user_id)
        ON DELETE CASCADE,
    CONSTRAINT fk_user_invites_creator
        FOREIGN KEY (created_by) REFERENCES users (user_id)
        ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS invite_rate_limits (
    request_key CHAR(64) NOT NULL,
    window_started_at DATETIME NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (request_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
