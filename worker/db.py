import os
from contextlib import contextmanager

import requests


def _require_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required env var: {name}")
    return value


def get_nhost_subdomain() -> str:
    return _require_env("NHOST_SUBDOMAIN")


def get_nhost_region() -> str:
    return _require_env("NHOST_REGION")


def get_nhost_admin_secret() -> str:
    return _require_env("NHOST_ADMIN_SECRET")


def get_graphql_url() -> str:
    subdomain = get_nhost_subdomain()
    region = get_nhost_region()
    return f"https://{subdomain}.nhost.run/v1/graphql"


def graphql_request(query: str, variables: dict = None):
    url = get_graphql_url()
    headers = {
        "Content-Type": "application/json",
        "x-hasura-admin-secret": get_nhost_admin_secret(),
    }
    data = {"query": query}
    if variables:
        data["variables"] = variables
    response = requests.post(url, json=data, headers=headers)
    response.raise_for_status()
    return response.json()


@contextmanager
def get_conn():
    # Return a dummy context, since we're not using connections anymore
    yield None
