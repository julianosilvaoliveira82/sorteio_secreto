-- SQL to create the draws table
-- Run this in the Supabase SQL Editor

CREATE TABLE IF NOT EXISTS draws (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    created_at timestamptz DEFAULT now(),
    admin_pin text NOT NULL,
    payload jsonb NOT NULL
);

-- Optional: Enable RLS and policies if needed,
-- but for now the anon key should work if RLS is off or configured.
-- ALTER TABLE draws ENABLE ROW LEVEL SECURITY;
