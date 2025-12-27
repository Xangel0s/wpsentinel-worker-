from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ScanJob:
    id: str
    target_url: str


TAKE_JOB_SQL = """
WITH next_job AS (
  SELECT id, target_url
  FROM public.scans
  WHERE status = 'queued'
  ORDER BY created_at ASC
  FOR UPDATE SKIP LOCKED
  LIMIT 1
)
UPDATE public.scans s
SET status = 'running',
    started_at = NOW(),
    error_message = NULL
FROM next_job
WHERE s.id = next_job.id
RETURNING s.id::text, s.target_url;
"""


def take_one_job(conn) -> ScanJob | None:
    with conn.cursor() as cur:
        cur.execute(TAKE_JOB_SQL)
        row = cur.fetchone()
        if not row:
            return None
        return ScanJob(id=row[0], target_url=row[1])


def mark_succeeded(conn, scan_id: str, vulnerabilities_count: int):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE public.scans
            SET status = 'succeeded',
                finished_at = NOW(),
                vulnerabilities_count = %s
            WHERE id = %s
            """,
            (vulnerabilities_count, scan_id),
        )


def mark_failed(conn, scan_id: str, error_message: str):
    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE public.scans
            SET status = 'failed',
                finished_at = NOW(),
                error_message = %s
            WHERE id = %s
            """,
            (error_message, scan_id),
        )


def insert_finding(conn, scan_id: str, severity: str, title: str, description: str | None, evidence: str | None, recommendation: str | None):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO public.scan_findings (scan_id, severity, title, description, evidence, recommendation)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (scan_id, severity, title, description, evidence, recommendation),
        )
