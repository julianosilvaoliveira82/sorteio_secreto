ALTER TABLE public.participants
ADD COLUMN IF NOT EXISTS opened_at timestamptz NULL;
