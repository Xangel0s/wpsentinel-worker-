-- Migration to add metadata column to scans table
-- Run this in Supabase SQL Editor to support scan metrics

-- Add metadata column if it doesn't exist
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 
    FROM information_schema.columns 
    WHERE table_name = 'scans' 
      AND column_name = 'metadata'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.scans 
    ADD COLUMN metadata jsonb;
  END IF;
END $$;

-- Update constraint to include 'completed' status
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'scans_status_check'
  ) THEN
    ALTER TABLE public.scans
      DROP CONSTRAINT scans_status_check;
  END IF;
END $$;

-- Add updated constraint with completed status
ALTER TABLE public.scans
  ADD CONSTRAINT scans_status_check
  CHECK (status IN ('pending', 'in_progress', 'completed', 'failed'));

-- Verify the table structure
SELECT column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_name = 'scans' 
  AND table_schema = 'public'
ORDER BY ordinal_position;
