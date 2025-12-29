-- Migration to add scan feedback table
-- Run this in Supabase SQL Editor for feedback system

-- Create scan_feedback table
CREATE TABLE IF NOT EXISTS public.scan_feedback (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  user_id uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  feedback_type text NOT NULL CHECK (feedback_type IN ('like', 'dislike')),
  created_at timestamp with time zone NOT NULL DEFAULT now(),
  comment text
);

-- Add unique constraint to prevent duplicate feedback per scan per user
ALTER TABLE public.scan_feedback 
  ADD CONSTRAINT unique_scan_user_feedback 
  UNIQUE (scan_id, user_id);

-- Enable RLS
ALTER TABLE public.scan_feedback ENABLE ROW LEVEL SECURITY;

-- Create policy for users to manage their own feedback
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'scan_feedback'
      AND policyname = 'Users can manage their own feedback'
  ) THEN
    CREATE POLICY "Users can manage their own feedback"
      ON public.scan_feedback
      FOR ALL
      USING (
        user_id = auth.uid() OR 
        (user_id IS NULL AND auth.uid() IS NULL)
      );
  END IF;
END $$;

-- Create policy for anonymous feedback (no user_id)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'scan_feedback'
      AND policyname = 'Anonymous users can submit feedback'
  ) THEN
    CREATE POLICY "Anonymous users can submit feedback"
      ON public.scan_feedback
      FOR INSERT
      WITH CHECK (user_id IS NULL AND auth.uid() IS NULL);
  END IF;
END $$;

-- Verify table structure
SELECT column_name, data_type, is_nullable
FROM information_schema.columns 
WHERE table_name = 'scan_feedback' 
  AND table_schema = 'public'
ORDER BY ordinal_position;
