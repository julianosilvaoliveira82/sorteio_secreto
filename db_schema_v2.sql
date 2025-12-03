-- SQL for Amigo Secreto V2

-- Table 1: Draws (Stores Admin/Config info)
CREATE TABLE IF NOT EXISTS draws (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    created_at timestamptz DEFAULT now(),
    admin_pin text NOT NULL,
    reveal_at timestamptz
);

-- Table 2: Participants (Stores individual states)
CREATE TABLE IF NOT EXISTS participants (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    draw_id uuid REFERENCES draws(id) ON DELETE CASCADE,
    name text NOT NULL,

    -- Encrypted target name (Accessible by User PIN)
    encrypted_target text NOT NULL,

    -- Encrypted target name (Accessible by Admin PIN for recovery/reset)
    admin_recovery_blob text NOT NULL,

    pin_initial text NOT NULL,      -- Visible to Admin
    pin_final text,                 -- Secret (User set)
    must_change_pin boolean DEFAULT true,
    created_at timestamptz DEFAULT now()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_participants_draw_id ON participants(draw_id);
