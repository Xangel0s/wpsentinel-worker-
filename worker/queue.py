from __future__ import annotations

import json
from dataclasses import dataclass

from .db import graphql_request


@dataclass
class ScanJob:
    id: str
    target_url: str


GET_PENDING_SCAN_QUERY = """
query GetPendingScan {
  scans(where: {status: {_eq: "pending"}}, order_by: {created_at: asc}, limit: 1) {
    id
    target_url
  }
}
"""

UPDATE_SCAN_MUTATION = """
mutation UpdateScan($id: uuid!, $status: String!, $started_at: timestamptz, $finished_at: timestamptz, $vulnerabilities_count: Int, $metadata: jsonb, $error_message: String) {
  update_scans(where: {id: {_eq: $id}}, _set: {status: $status, started_at: $started_at, finished_at: $finished_at, vulnerabilities_count: $vulnerabilities_count, metadata: $metadata, error_message: $error_message}) {
    affected_rows
  }
}
"""

INSERT_FINDING_MUTATION = """
mutation InsertFinding($scan_id: uuid!, $severity: String!, $title: String!, $description: String, $evidence: String, $recommendation: String) {
  insert_scan_findings_one(object: {scan_id: $scan_id, severity: $severity, title: $title, description: $description, evidence: $evidence, recommendation: $recommendation}) {
    id
  }
}
"""


def take_one_job() -> ScanJob | None:
    response = graphql_request(GET_PENDING_SCAN_QUERY)
    scans = response.get("data", {}).get("scans", [])
    if not scans:
        return None
    scan = scans[0]
    # Update to in_progress
    variables = {
        "id": scan["id"],
        "status": "in_progress",
        "started_at": "now()",
    }
    graphql_request(UPDATE_SCAN_MUTATION, variables)
    return ScanJob(id=scan["id"], target_url=scan["target_url"])


def mark_succeeded(scan_id: str, vulnerabilities_count: int, metrics_dict: dict | None = None):
    variables = {
        "id": scan_id,
        "status": "completed",
        "finished_at": "now()",
        "vulnerabilities_count": vulnerabilities_count,
        "metadata": json.dumps(metrics_dict) if metrics_dict else None,
    }
    graphql_request(UPDATE_SCAN_MUTATION, variables)


def mark_failed(scan_id: str, error_message: str):
    variables = {
        "id": scan_id,
        "status": "failed",
        "finished_at": "now()",
        "error_message": error_message,
    }
    graphql_request(UPDATE_SCAN_MUTATION, variables)


def insert_finding(scan_id: str, severity: str, title: str, description: str | None, evidence: str | None, recommendation: str | None):
    variables = {
        "scan_id": scan_id,
        "severity": severity,
        "title": title,
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
    }
    graphql_request(INSERT_FINDING_MUTATION, variables)
