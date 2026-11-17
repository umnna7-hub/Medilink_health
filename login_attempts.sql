CREATE TABLE IF NOT EXISTS login_attempts (
    email VARCHAR(150) NOT NULL,
    failed_count INT NOT NULL DEFAULT 0,
    locked_until DATETIME NULL,
    PRIMARY KEY (email)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
