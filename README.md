# wpsentinel-worker

Python worker for WpSentinel (Option A: Postgres queue).

## What it does

- Polls the `public.scans` table for rows with `status = 'queued'`.
- Locks one job at a time using `FOR UPDATE SKIP LOCKED`.
- Marks it as `running` and performs a lightweight WordPress security check (HTTP-based).
- Writes findings to `public.scan_findings`.
- Updates the scan row (`status`, `vulnerabilities_count`, timestamps).

This repository is designed to run as a Docker container (recommended for Coolify).

## Environment variables

- `DATABASE_URL` (required)
  - Postgres connection string with a role that can:
    - `SELECT/UPDATE` on `public.scans`
    - `INSERT` on `public.scan_findings`

Optional:

- `POLL_INTERVAL_SECONDS` (default: 5)
- `HTTP_TIMEOUT_SECONDS` (default: 15)
- `USER_AGENT` (default: `WpSentinelWorker/1.0`)

## Quick test (no database)

You can validate the container and the scanner logic without wiring `DATABASE_URL`.

Run a single scan and exit:

```bash
docker build -t wpsentinel-worker .
docker run --rm -e TEST_URL="https://wordpress.org" wpsentinel-worker
```

This prints findings to stdout and terminates.

## Database migration

Apply `migrations/001_scan_queue.sql` in Supabase SQL Editor.

## Run locally

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export DATABASE_URL="postgresql://..."
python -m worker
```

## Run with Docker

```bash
docker build -t wpsentinel-worker .
docker run --rm -e DATABASE_URL="postgresql://..." wpsentinel-worker
```

## Coolify deployment checklist

1. Create a new application from this repository.
2. Use the included `Dockerfile`.
3. Set env vars:

* `DATABASE_URL` (required for worker mode)
* `POLL_INTERVAL_SECONDS` (optional)
* `HTTP_TIMEOUT_SECONDS` (optional)

4. Scale replicas as needed. The queue uses `FOR UPDATE SKIP LOCKED`, so multiple replicas can safely run in parallel.
