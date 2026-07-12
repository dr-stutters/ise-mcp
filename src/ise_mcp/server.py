"""Cisco ISE (Identity Services Engine) MCP server entry point."""

from __future__ import annotations

import argparse

from mcp.server.fastmcp import FastMCP

from .client import ISEClient
from .config import load_settings
from .spec import SpecCache
from .tools import register_all


def build_server() -> FastMCP:
    settings = load_settings()
    client = ISEClient(settings)
    spec = SpecCache(client)
    mcp = FastMCP(
        "ise",
        instructions=(
            "Tools for Cisco Identity Services Engine (ISE) across its three REST "
            "surfaces (all HTTP Basic auth): OpenAPI (port 443, /api/...) for "
            "endpoints, TrustSec/SGTs, policy sets and deployment; ERS (port 9060, "
            "/ers/config/...) for network devices (NADs), internal users and "
            "identity/endpoint groups; and MnT (port 443, /admin/API/mnt/...) for "
            "read-only session monitoring. Start with ise_check_surfaces - ERS "
            "(9060) is firewalled off in some deployments, and those tools then time "
            "out. The OpenAPI surface is schema-driven: use ise_search_spec + "
            "ise_get_definition to find endpoints and exact fields/enums across the "
            "OpenAPI groups, and ise_openapi_call / ise_ers_call / ise_mnt_call for "
            "anything without a dedicated tool."
        ),
    )
    register_all(mcp, client, spec)
    return mcp


def main() -> None:
    parser = argparse.ArgumentParser(description="Cisco ISE MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport (default: stdio)",
    )
    args = parser.parse_args()
    build_server().run(transport=args.transport)


if __name__ == "__main__":
    main()
