from __future__ import annotations

import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from .store import ConflictError, NotFoundError, PromptPatchError, PromptStore, ValidationError


mcp = FastMCP(
    "PromptPatch",
    instructions=(
        "Local-first prompt diffs, rollback, releases, and security scans. "
        "Save prompt snapshots, inspect changes, and recover known-good versions."
    ),
)

_STORE: PromptStore | None = None


def get_store() -> PromptStore:
    global _STORE
    if _STORE is None:
        _STORE = PromptStore.from_env()
    return _STORE


def _run_store_call(call: Any) -> dict[str, Any]:
    try:
        return call()
    except (ValidationError, NotFoundError, ConflictError) as exc:
        raise ValueError(str(exc)) from exc
    except PromptPatchError as exc:
        raise RuntimeError(str(exc)) from exc


@mcp.tool()
def save_prompt(
    name: str,
    content: str,
    message: str = "",
    allow_duplicate: bool = False,
    security_mode: str = "",
) -> dict[str, Any]:
    """Save a versioned prompt snapshot. security_mode is block, warn, off, or empty default."""
    return _run_store_call(
        lambda: get_store().save_prompt(
            name,
            content,
            message,
            allow_duplicate=allow_duplicate,
            security_mode=security_mode or None,
        )
    )


@mcp.tool()
def get_prompt(name: str, ref: str = "HEAD") -> dict[str, Any]:
    """Retrieve prompt content by HEAD, version number, id:123, or tag."""
    return _run_store_call(lambda: get_store().get_prompt(name, ref))


@mcp.tool()
def list_versions(name: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    """List versions for a prompt, newest first."""
    return _run_store_call(lambda: get_store().list_versions(name, limit=limit, offset=offset))


@mcp.tool()
def diff_versions(
    name: str,
    from_ref: str,
    to_ref: str,
    context_lines: int = 3,
) -> dict[str, Any]:
    """Return a unified diff between two refs for the same prompt."""
    return _run_store_call(
        lambda: get_store().diff_versions(
            name,
            from_ref,
            to_ref,
            context_lines=context_lines,
        )
    )


@mcp.tool()
def rollback(name: str, ref: str, message: str | None = None) -> dict[str, Any]:
    """Restore an older prompt by creating a new version with that content."""
    return _run_store_call(lambda: get_store().rollback(name, ref, message))


@mcp.tool()
def tag_release(
    name: str,
    ref: str,
    tag: str,
    message: str = "",
    force: bool = False,
) -> dict[str, Any]:
    """Attach a human-readable tag to a prompt version. Set force=true to move it."""
    return _run_store_call(
        lambda: get_store().tag_release(name, ref, tag, message, force=force)
    )


@mcp.tool()
def list_prompts() -> dict[str, Any]:
    """List all tracked prompt names and latest versions."""
    return _run_store_call(lambda: get_store().list_prompts())


@mcp.tool()
def db_info() -> dict[str, Any]:
    """Return local database path and count information."""
    return _run_store_call(lambda: get_store().db_info())


@mcp.tool()
def scan_prompt_security(
    content: str = "",
    name: str = "",
    ref: str = "HEAD",
    security_mode: str = "",
) -> dict[str, Any]:
    """Scan raw content or a stored prompt for injection, exfiltration, and secrets."""
    return _run_store_call(
        lambda: get_store().scan_prompt_security(
            content=content if content != "" else None,
            name=name if name != "" else None,
            ref=ref,
            security_mode=security_mode or None,
        )
    )


def main() -> None:
    transport = os.environ.get("PROMPTPATCH_TRANSPORT", "stdio")
    mcp.run(transport=transport)


if __name__ == "__main__":
    main()
