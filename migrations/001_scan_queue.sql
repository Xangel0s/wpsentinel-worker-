ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'queued',
  ADD COLUMN IF NOT EXISTS started_at timestamp with time zone,
  ADD COLUMN IF NOT EXISTS finished_at timestamp with time zone,
  ADD COLUMN IF NOT EXISTS error_message text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'scans_status_check'
  ) THEN
    ALTER TABLE public.scans
      ADD CONSTRAINT scans_status_check
      CHECK (status IN ('queued', 'running', 'succeeded', 'failed'));
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS public.scan_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  severity text NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
  title text NOT NULL,
  description text,
  evidence text,
  recommendation text,
  created_at timestamp with time zone NOT NULL DEFAULT now()
);

ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'scan_findings'
      AND policyname = 'Users can view findings for own scans'
  ) THEN
    CREATE POLICY "Users can view findings for own scans"
      ON public.scan_findings
      FOR SELECT
      USING (
        EXISTS (
          SELECT 1
          FROM public.scans s
          WHERE s.id = scan_findings.scan_id
            AND (s.user_id = auth.uid() OR s.user_id IS NULL)
        )
      );
  END IF;
END $$;
