-- Migration to add missing columns to scan_findings table
-- Run this in Supabase SQL Editor to fix the evidence column error

-- Add missing columns if they don't exist
DO $$
BEGIN
  -- Add evidence column
  IF NOT EXISTS (
    SELECT 1 
    FROM information_schema.columns 
    WHERE table_name = 'scan_findings' 
      AND column_name = 'evidence'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.scan_findings 
    ADD COLUMN evidence text;
  END IF;

  -- Add recommendation column if it doesn't exist
  IF NOT EXISTS (
    SELECT 1 
    FROM information_schema.columns 
    WHERE table_name = 'scan_findings' 
      AND column_name = 'recommendation'
      AND table_schema = 'public'
  ) THEN
    ALTER TABLE public.scan_findings 
    ADD COLUMN recommendation text;
  END IF;
END $$;

-- Verify the table structure
SELECT column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_name = 'scan_findings' 
  AND table_schema = 'public'
ORDER BY ordinal_position;
