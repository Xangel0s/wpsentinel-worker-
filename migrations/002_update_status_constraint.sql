-- Migration to update status constraint from queued/running to pending/in_progress
-- Run this in Supabase SQL Editor to update existing production database

-- First, update any existing records with old status values
UPDATE public.scans 
SET status = 'pending' 
WHERE status = 'queued';

UPDATE public.scans 
SET status = 'in_progress' 
WHERE status = 'running';

-- Drop the old constraint if it exists
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

-- Add the updated constraint with new status values
ALTER TABLE public.scans
  ADD CONSTRAINT scans_status_check
  CHECK (status IN ('pending', 'in_progress', 'succeeded', 'failed'));

-- Verify the constraint
SELECT conname, pg_get_constraintdef(oid) 
FROM pg_constraint 
WHERE conname = 'scans_status_check';
