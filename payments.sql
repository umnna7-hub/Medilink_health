CREATE TABLE IF NOT EXISTS payments (
    payment_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    patient_id INT NOT NULL,
    appointment_id INT NOT NULL,
    amount DECIMAL(10, 2) UNSIGNED NOT NULL,
    currency CHAR(3) NOT NULL DEFAULT 'PKR',
    status ENUM('Pending', 'Successful', 'Failed') NOT NULL DEFAULT 'Pending',
    provider VARCHAR(32) NOT NULL DEFAULT 'simulation',
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (payment_id),
    KEY idx_payments_patient_history (patient_id, created_at),
    UNIQUE KEY uq_payments_appointment (appointment_id),
    CONSTRAINT fk_payments_patient
        FOREIGN KEY (patient_id) REFERENCES users (user_id)
        ON UPDATE CASCADE ON DELETE RESTRICT,
    CONSTRAINT fk_payments_appointment
        FOREIGN KEY (appointment_id) REFERENCES appointments (appointment_id)
        ON UPDATE CASCADE ON DELETE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
