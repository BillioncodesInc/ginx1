-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Add IMAP fields to SMTP table for lead extraction
ALTER TABLE smtp ADD COLUMN imap_host VARCHAR(255) DEFAULT '';
ALTER TABLE smtp ADD COLUMN imap_port INT DEFAULT 0;
ALTER TABLE smtp ADD COLUMN imap_username VARCHAR(255) DEFAULT '';
ALTER TABLE smtp ADD COLUMN imap_password VARCHAR(255) DEFAULT '';
ALTER TABLE smtp ADD COLUMN imap_tls BOOLEAN DEFAULT FALSE;
ALTER TABLE smtp ADD COLUMN imap_ignore_cert_errors BOOLEAN DEFAULT FALSE;

-- Create extracted_leads table
CREATE TABLE IF NOT EXISTS extracted_leads (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    smtp_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255) DEFAULT '',
    source VARCHAR(50) DEFAULT 'inbox',
    extracted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    imported_to_group_id BIGINT DEFAULT 0,
    INDEX idx_extracted_leads_smtp_id (smtp_id),
    INDEX idx_extracted_leads_user_id (user_id),
    INDEX idx_extracted_leads_email (email),
    FOREIGN KEY (smtp_id) REFERENCES smtp(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Create lead_extraction_jobs table
CREATE TABLE IF NOT EXISTS lead_extraction_jobs (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    smtp_id BIGINT NOT NULL,
    user_id BIGINT NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    folders TEXT,
    days_back INT DEFAULT 160,
    total_emails INT DEFAULT 0,
    processed_emails INT DEFAULT 0,
    leads_found INT DEFAULT 0,
    error_message TEXT,
    started_at DATETIME,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_lead_extraction_jobs_smtp_id (smtp_id),
    INDEX idx_lead_extraction_jobs_user_id (user_id),
    INDEX idx_lead_extraction_jobs_status (status),
    FOREIGN KEY (smtp_id) REFERENCES smtp(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP TABLE IF EXISTS lead_extraction_jobs;
DROP TABLE IF EXISTS extracted_leads;

ALTER TABLE smtp DROP COLUMN imap_host;
ALTER TABLE smtp DROP COLUMN imap_port;
ALTER TABLE smtp DROP COLUMN imap_username;
ALTER TABLE smtp DROP COLUMN imap_password;
ALTER TABLE smtp DROP COLUMN imap_tls;
ALTER TABLE smtp DROP COLUMN imap_ignore_cert_errors;
