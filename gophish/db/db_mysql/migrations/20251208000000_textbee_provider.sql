
-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
-- Add provider type and TextBee fields to sms table
ALTER TABLE sms ADD COLUMN `provider` varchar(50) DEFAULT 'twilio';
ALTER TABLE sms ADD COLUMN `textbee_api_key` varchar(255);
ALTER TABLE sms ADD COLUMN `textbee_device_id` varchar(255);

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back

