import os
import time

from .db import get_conn
from .queue import insert_finding, mark_failed, mark_succeeded, take_one_job
from .scanner import scan_target


def _get_int(name: str, default: int) -> int:
    v = os.getenv(name)
    if not v:
        return default
    return int(v)


def _get_str(name: str, default: str) -> str:
    return os.getenv(name) or default


def main():
    test_url = os.getenv("TEST_URL")
    poll_interval = _get_int("POLL_INTERVAL_SECONDS", 5)
    timeout_seconds = _get_int("HTTP_TIMEOUT_SECONDS", 15)
    user_agent = _get_str("USER_AGENT", "WpSentinelWorker/1.0")

    if test_url:
        findings = scan_target(test_url, timeout_seconds=timeout_seconds, user_agent=user_agent)
        for f in findings:
            print(f"[{f.severity.upper()}] {f.title}")
            if f.description:
                print(f"  description: {f.description}")
            if f.evidence:
                print(f"  evidence: {f.evidence}")
            if f.recommendation:
                print(f"  recommendation: {f.recommendation}")
        return

    while True:
        with get_conn() as conn:
            try:
                job = take_one_job(conn)
                if not job:
                    conn.commit()
                    time.sleep(poll_interval)
                    continue

                findings = scan_target(job.target_url, timeout_seconds=timeout_seconds, user_agent=user_agent)

                for f in findings:
                    insert_finding(
                        conn,
                        scan_id=job.id,
                        severity=f.severity,
                        title=f.title,
                        description=f.description,
                        evidence=f.evidence,
                        recommendation=f.recommendation,
                    )

                # Count anything that isn't informational
                vulns = sum(1 for f in findings if f.severity in {"low", "medium", "high", "critical"})
                mark_succeeded(conn, scan_id=job.id, vulnerabilities_count=vulns)
                conn.commit()

            except Exception as e:
                # Best-effort: if we have a job in-process, it has already been marked running
                # and should be marked failed.
                try:
                    if "job" in locals() and locals()["job"] is not None:
                        mark_failed(conn, scan_id=locals()["job"].id, error_message=str(e))
                        conn.commit()
                except Exception:
                    conn.rollback()

                time.sleep(poll_interval)


if __name__ == "__main__":
    main()
