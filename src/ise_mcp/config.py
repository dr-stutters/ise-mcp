"""Configuration for the ISE MCP server, loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    base_url: str
    username: str
    password: str
    ers_port: int
    verify_ssl: bool
    timeout: float


def load_settings() -> Settings:
    """Build settings from ISE_* environment variables.

    A local .env is honored - both next to this project and in the current
    working directory (so the server works standalone and when launched from a
    parent project like cml-mcp via `uv run --directory`).
    """
    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    load_dotenv()

    host = os.environ.get("ISE_URL") or os.environ.get("ISE_HOST", "")
    if not host:
        raise RuntimeError(
            "ISE_URL is not set. Set ISE_URL (e.g. https://192.0.2.30), "
            "ISE_USERNAME and ISE_PASSWORD in the environment or a .env file."
        )
    if not host.startswith(("http://", "https://")):
        host = f"https://{host}"
    host = host.rstrip("/")

    username = os.environ.get("ISE_USERNAME", "")
    password = os.environ.get("ISE_PASSWORD", "")
    if not username or not password:
        raise RuntimeError("ISE_USERNAME and ISE_PASSWORD must be set.")

    # ERS is served on both 443 (modern, recommended) and the legacy 9060.
    # Default to 443: 9060 is deprecated (ISE 3.x) and often firewalled/off.
    ers_port = int(os.environ.get("ISE_ERS_PORT", "443"))
    verify = os.environ.get("ISE_VERIFY_SSL", "false").strip().lower() in ("1", "true", "yes")
    timeout = float(os.environ.get("ISE_TIMEOUT", "60"))

    return Settings(
        base_url=host,
        username=username,
        password=password,
        ers_port=ers_port,
        verify_ssl=verify,
        timeout=timeout,
    )
