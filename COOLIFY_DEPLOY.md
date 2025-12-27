# 🚀 Coolify Deployment Guide

> ⚠️ **Important:** This is a **background worker** container, NOT a web server.
> It does NOT need Traefik/HTTP routing, domain, or SSL certificates.
> It only needs `DATABASE_URL` to connect to Supabase.

> [!CAUTION]
> **Use the IPv4 Pooler (Port 6543)**. Direct connections (Port 5432) in Supabase often use IPv6, which may be "Unreachable" in many Docker/Coolify setups.

## Step 1: Get your Supabase Connection String

1. Go to **Supabase Dashboard** → **Project Settings** → **Database**
2. Copy the **Connection String (URI)** under "Connection Pooling" (Mode: Transaction)
3. It looks like:
   ```
   postgresql://postgres.[PROJECT-REF]:[PASSWORD]@aws-0-us-east-1.pooler.supabase.com:6543/postgres
   ```

> ⚠️ **Important:** Use the **Transaction mode** pooler URL, NOT the direct connection.

---

## Step 2: Apply Migration to Supabase

Before deploying, ensure your database has the required schema:

1. Go to **Supabase Dashboard** → **SQL Editor**
2. Paste the contents of `migrations/001_scan_queue.sql`
3. Run it

This adds:
- `status`, `started_at`, `finished_at`, `error_message` to `scans` table
- Creates `scan_findings` table

---

## Step 3: Create Application in Coolify

1. **New Resource** → **Public Repository** (or Private if your repo is private)
2. **Repository URL:** `https://github.com/Xangel0s/wpsentinel-worker-.git`
3. **Build Pack:** Dockerfile ✅ (auto-detected)
4. **IMPORTANT - Worker Settings:**
   - ❌ **Disable "Expose to Internet"** (no domain/Traefik needed)
   - ✅ **Health Check:** Not required (worker loops forever)
   - ✅ **Restart Policy:** Always

5. **Environment Variables:**

| Variable | Value | Required |
|----------|-------|----------|
| `DATABASE_URL` | `postgresql://postgres.[ref]:[pass]@...` | ✅ Yes |
| `POLL_INTERVAL_SECONDS` | `5` | Optional |
| `HTTP_TIMEOUT_SECONDS` | `15` | Optional |
| `USER_AGENT` | `WpSentinelWorker/1.0` | Optional |

---

## Step 4: Configure Resources

**Recommended settings:**
- **CPU:** 0.5 cores
- **Memory:** 256 MB
- **Replicas:** 1 (scale as needed - queue is safe for parallel workers)

---

## Step 5: Deploy

Click **Deploy** and monitor logs. You should see:

```
INFO:worker:Starting worker, polling every 5s
INFO:worker:No jobs, sleeping...
```

When a scan is queued, you'll see:

```
INFO:worker:Processing scan abc-123 for https://example.com
INFO:worker:Scan completed, 3 vulnerabilities found
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `Missing required env var: DATABASE_URL` | Set DATABASE_URL in Coolify env vars |
| `Connection refused` | Check Supabase connection string, ensure pooler mode |
| `Permission denied` | Ensure RLS policies allow service role OR use service_role key |

---

## Using Service Role (Recommended for Production)

For the worker to bypass RLS and update any scan:

1. Get your **Service Role Key** from Supabase (Settings → API)
2. The worker connects directly via `DATABASE_URL`, so RLS doesn't apply to direct Postgres connections with the right permissions

Alternatively, add explicit policies:
```sql
CREATE POLICY "Service can update scans"
ON public.scans FOR UPDATE
USING (true);
```
