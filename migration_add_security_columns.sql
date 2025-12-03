-- Add missing security columns required by the app
ALTER TABLE participants ADD COLUMN failed_attempts INT NOT NULL DEFAULT 0;
ALTER TABLE participants ADD COLUMN last_activity_at TIMESTAMPTZ NULL;
ALTER TABLE participants ADD COLUMN locked_until TIMESTAMPTZ NULL;
