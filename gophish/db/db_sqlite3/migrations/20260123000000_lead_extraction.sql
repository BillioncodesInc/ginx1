-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied

-- Add IMAP fields to SMTP table for lead extraction
ALTER TABLE smtp ADD COLUMN imap_host VARCHAR(255) DEFAULT '';
ALTER TABLE smtp ADD COLUMN imap_port INTEGER DEFAULT 0;
ALTER TABLE smtp ADD COLUMN imap_username VARCHAR(255) DEFAULT '';
ALTER TABLE smtp ADD COLUMN imap_password VARCHAR(255) DEFAULT '';
ALTER TABLE smtp ADD COLUMN imap_tls BOOLEAN DEFAULT 0;
ALTER TABLE smtp ADD COLUMN imap_ignore_cert_errors BOOLEAN DEFAULT 0;

-- Create extracted_leads table
CREATE TABLE IF NOT EXISTS extracted_leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    smtp_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    email VARCHAR(255) NOT NULL,
    name VARCHAR(255) DEFAULT '',
    source VARCHAR(50) DEFAULT 'inbox',
    extracted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    imported_to_group_id INTEGER DEFAULT 0,
    FOREIGN KEY (smtp_id) REFERENCES smtp(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_extracted_leads_smtp_id ON extracted_leads(smtp_id);
CREATE INDEX IF NOT EXISTS idx_extracted_leads_user_id ON extracted_leads(user_id);
CREATE INDEX IF NOT EXISTS idx_extracted_leads_email ON extracted_leads(email);

-- Create lead_extraction_jobs table
CREATE TABLE IF NOT EXISTS lead_extraction_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    smtp_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    folders TEXT DEFAULT '[]',
    days_back INTEGER DEFAULT 160,
    total_emails INTEGER DEFAULT 0,
    processed_emails INTEGER DEFAULT 0,
    leads_found INTEGER DEFAULT 0,
    error_message TEXT DEFAULT '',
    started_at DATETIME,
    completed_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (smtp_id) REFERENCES smtp(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_lead_extraction_jobs_smtp_id ON lead_extraction_jobs(smtp_id);
CREATE INDEX IF NOT EXISTS idx_lead_extraction_jobs_user_id ON lead_extraction_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_lead_extraction_jobs_status ON lead_extraction_jobs(status);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

DROP INDEX IF EXISTS idx_lead_extraction_jobs_status;
DROP INDEX IF EXISTS idx_lead_extraction_jobs_user_id;
DROP INDEX IF EXISTS idx_lead_extraction_jobs_smtp_id;
DROP TABLE IF EXISTS lead_extraction_jobs;

DROP INDEX IF EXISTS idx_extracted_leads_email;
DROP INDEX IF EXISTS idx_extracted_leads_user_id;
DROP INDEX IF EXISTS idx_extracted_leads_smtp_id;
DROP TABLE IF EXISTS extracted_leads;

-- Note: SQLite doesn't support DROP COLUMN, so we can't easily rollback the SMTP changes
-- The columns will remain but be unused if rolled back
