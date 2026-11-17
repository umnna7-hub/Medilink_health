ALTER TABLE doctors
    ADD COLUMN is_active BOOLEAN NOT NULL DEFAULT TRUE AFTER specialty,
    ADD COLUMN user_id INT NULL AFTER is_active,
    ADD UNIQUE KEY uq_doctors_user_id (user_id),
    ADD CONSTRAINT fk_doctors_user
        FOREIGN KEY (user_id) REFERENCES users (user_id)
        ON DELETE RESTRICT ON UPDATE CASCADE;
