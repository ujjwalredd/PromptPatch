from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .security import compact_security_report, default_security_mode, scan_prompt_content


class PromptPatchError(Exception):
    """Base error for PromptPatch operations."""


class ValidationError(PromptPatchError):
    """Raised when user input is invalid."""


class NotFoundError(PromptPatchError):
    """Raised when a prompt, version, or tag cannot be found."""


class ConflictError(PromptPatchError):
    """Raised when an operation would overwrite existing data."""


class SecurityError(ValidationError):
    """Raised when prompt content violates the configured security policy."""


_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,63}$")
_DEFAULT_MAX_CONTENT_BYTES = 1_000_000
_MAX_MESSAGE_CHARS = 2_000
_MAX_METADATA_BYTES = 20_000


def default_db_path() -> Path:
    raw_path = os.environ.get("PROMPTPATCH_DB_PATH")
    if raw_path:
        return Path(raw_path).expanduser()
    return Path(".promptpatch") / "prompts.sqlite3"


def default_max_content_bytes() -> int:
    raw_limit = os.environ.get("PROMPTPATCH_MAX_CONTENT_BYTES")
    if not raw_limit:
        return _DEFAULT_MAX_CONTENT_BYTES
    try:
        limit = int(raw_limit)
    except ValueError as exc:
        raise ValidationError("PROMPTPATCH_MAX_CONTENT_BYTES must be an integer") from exc
    if limit < 1 or limit > 50_000_000:
        raise ValidationError("PROMPTPATCH_MAX_CONTENT_BYTES must be between 1 and 50000000")
    return limit


@dataclass(frozen=True)
class ResolvedVersion:
    id: int
    name: str
    version: int
    content: str
    content_sha256: str
    message: str
    metadata: dict[str, Any]
    created_at: str


class PromptStore:
    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        max_content_bytes: int | None = None,
        initialize: bool = True,
    ) -> None:
        self.db_path = Path(db_path).expanduser() if db_path is not None else default_db_path()
        self.max_content_bytes = (
            max_content_bytes if max_content_bytes is not None else default_max_content_bytes()
        )
        self._write_lock = threading.RLock()
        if initialize:
            self.initialize()

    @classmethod
    def from_env(cls) -> "PromptStore":
        return cls(default_db_path(), max_content_bytes=default_max_content_bytes())

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS prompt_versions (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  version INTEGER NOT NULL CHECK (version > 0),
                  content TEXT NOT NULL,
                  content_sha256 TEXT NOT NULL,
                  message TEXT NOT NULL DEFAULT '',
                  metadata_json TEXT NOT NULL DEFAULT '{}',
                  created_at TEXT NOT NULL,
                  UNIQUE(name, version)
                );

                CREATE INDEX IF NOT EXISTS idx_prompt_versions_name_version
                  ON prompt_versions(name, version DESC);

                CREATE INDEX IF NOT EXISTS idx_prompt_versions_created_at
                  ON prompt_versions(created_at DESC);

                CREATE TABLE IF NOT EXISTS prompt_tags (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  tag TEXT NOT NULL,
                  version_id INTEGER NOT NULL REFERENCES prompt_versions(id) ON DELETE CASCADE,
                  message TEXT NOT NULL DEFAULT '',
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  UNIQUE(name, tag)
                );

                CREATE INDEX IF NOT EXISTS idx_prompt_tags_version_id
                  ON prompt_tags(version_id);

                PRAGMA user_version = 1;
                """
            )

    def save_prompt(
        self,
        name: str,
        content: str,
        message: str = "",
        *,
        metadata: dict[str, Any] | None = None,
        allow_duplicate: bool = False,
        security_mode: str | None = None,
    ) -> dict[str, Any]:
        safe_name = self._validate_name(name)
        safe_content = self._validate_content(content)
        safe_message = self._validate_message(message)
        security_report = self._scan_security(safe_content, security_mode)
        if security_report["blocked"]:
            raise SecurityError(_security_block_message(security_report))

        safe_metadata = dict(metadata or {})
        safe_metadata["promptpatch_security"] = compact_security_report(security_report)
        safe_metadata_json = self._validate_metadata(safe_metadata)
        content_hash = _sha256(safe_content)

        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                head = self._head_row(conn, safe_name)
                if head and not allow_duplicate and head["content_sha256"] == content_hash:
                    version = self._version_summary(conn, head, created=False)
                    conn.commit()
                    return {
                        "created": False,
                        "version": version,
                        "security": security_report,
                    }

                next_version = int(head["version"]) + 1 if head else 1
                created_at = _utc_now()
                cursor = conn.execute(
                    """
                    INSERT INTO prompt_versions
                      (name, version, content, content_sha256, message, metadata_json, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        safe_name,
                        next_version,
                        safe_content,
                        content_hash,
                        safe_message,
                        safe_metadata_json,
                        created_at,
                    ),
                )
                row = self._version_by_id(conn, int(cursor.lastrowid))
                if row is None:
                    raise PromptPatchError("Failed to read saved prompt version")
                version = self._version_summary(conn, row, created=True)
                conn.commit()
                return {
                    "created": True,
                    "version": version,
                    "security": security_report,
                }
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def get_prompt(self, name: str, ref: str | int | None = "HEAD") -> dict[str, Any]:
        safe_name = self._validate_name(name)
        with self._connect() as conn:
            row = self._resolve_version(conn, safe_name, ref)
            return {"version": self._version_summary(conn, row, include_content=True)}

    def list_versions(self, name: str, *, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        safe_name = self._validate_name(name)
        safe_limit = _validate_limit(limit)
        safe_offset = _validate_offset(offset)
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT *
                FROM prompt_versions
                WHERE name = ?
                ORDER BY version DESC
                LIMIT ? OFFSET ?
                """,
                (safe_name, safe_limit, safe_offset),
            ).fetchall()
            if not rows:
                if not self._prompt_exists(conn, safe_name):
                    raise NotFoundError(f"Prompt '{safe_name}' does not exist")
            return {
                "name": safe_name,
                "versions": [self._version_summary(conn, row) for row in rows],
                "limit": safe_limit,
                "offset": safe_offset,
            }

    def list_prompts(self) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                WITH latest AS (
                  SELECT name, MAX(version) AS latest_version, COUNT(*) AS version_count
                  FROM prompt_versions
                  GROUP BY name
                )
                SELECT pv.name, latest.version_count, pv.version AS latest_version,
                       pv.id AS latest_id, pv.content_sha256, pv.message, pv.created_at
                FROM prompt_versions pv
                JOIN latest
                  ON latest.name = pv.name
                 AND latest.latest_version = pv.version
                ORDER BY lower(pv.name)
                """
            ).fetchall()
            prompts = [
                {
                    "name": row["name"],
                    "version_count": row["version_count"],
                    "latest": {
                        "id": row["latest_id"],
                        "version": row["latest_version"],
                        "content_sha256": row["content_sha256"],
                        "message": row["message"],
                        "created_at": row["created_at"],
                    },
                }
                for row in rows
            ]
            return {"prompts": prompts, "count": len(prompts)}

    def diff_versions(
        self,
        name: str,
        from_ref: str | int,
        to_ref: str | int,
        *,
        context_lines: int = 3,
    ) -> dict[str, Any]:
        safe_name = self._validate_name(name)
        safe_context = _validate_context_lines(context_lines)
        with self._connect() as conn:
            from_row = self._resolve_version(conn, safe_name, from_ref)
            to_row = self._resolve_version(conn, safe_name, to_ref)

        from_lines = from_row["content"].splitlines(keepends=True)
        to_lines = to_row["content"].splitlines(keepends=True)
        diff_lines = list(
            difflib.unified_diff(
                from_lines,
                to_lines,
                fromfile=f"{safe_name}@v{from_row['version']}",
                tofile=f"{safe_name}@v{to_row['version']}",
                n=safe_context,
            )
        )
        additions = sum(
            1 for line in diff_lines if line.startswith("+") and not line.startswith("+++")
        )
        deletions = sum(
            1 for line in diff_lines if line.startswith("-") and not line.startswith("---")
        )
        return {
            "name": safe_name,
            "from": _row_ref(from_row),
            "to": _row_ref(to_row),
            "changed": bool(diff_lines),
            "stats": {"additions": additions, "deletions": deletions},
            "diff": "".join(diff_lines),
        }

    def rollback(
        self,
        name: str,
        ref: str | int,
        message: str | None = None,
    ) -> dict[str, Any]:
        safe_name = self._validate_name(name)
        with self._connect() as conn:
            target = self._resolve_version(conn, safe_name, ref)
            target_ref = _row_ref(target)

        rollback_message = (
            self._validate_message(message)
            if message is not None
            else f"Rollback {safe_name} to v{target['version']}"
        )
        saved = self.save_prompt(
            safe_name,
            target["content"],
            rollback_message,
            metadata={"rollback_to": target_ref},
            allow_duplicate=False,
            security_mode="warn",
        )
        return {"rolled_back_to": target_ref, "result": saved}

    def tag_release(
        self,
        name: str,
        ref: str | int,
        tag: str,
        message: str = "",
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        safe_name = self._validate_name(name)
        safe_tag = self._validate_tag(tag)
        safe_message = self._validate_message(message)

        with self._write_lock:
            conn = self._connect()
            try:
                conn.execute("BEGIN IMMEDIATE")
                target = self._resolve_version(conn, safe_name, ref)
                existing = conn.execute(
                    """
                    SELECT *
                    FROM prompt_tags
                    WHERE name = ? AND tag = ?
                    """,
                    (safe_name, safe_tag),
                ).fetchone()
                now = _utc_now()
                if existing and not force:
                    raise ConflictError(
                        f"Tag '{safe_tag}' already exists for prompt '{safe_name}'. "
                        "Pass force=true to move it."
                    )
                if existing:
                    conn.execute(
                        """
                        UPDATE prompt_tags
                        SET version_id = ?, message = ?, updated_at = ?
                        WHERE name = ? AND tag = ?
                        """,
                        (target["id"], safe_message, now, safe_name, safe_tag),
                    )
                    moved = True
                else:
                    conn.execute(
                        """
                        INSERT INTO prompt_tags
                          (name, tag, version_id, message, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (safe_name, safe_tag, target["id"], safe_message, now, now),
                    )
                    moved = False
                conn.commit()
                return {
                    "name": safe_name,
                    "tag": safe_tag,
                    "moved": moved,
                    "version": _row_ref(target),
                }
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()

    def db_info(self) -> dict[str, Any]:
        with self._connect() as conn:
            prompt_count = conn.execute(
                "SELECT COUNT(DISTINCT name) FROM prompt_versions"
            ).fetchone()[0]
            version_count = conn.execute("SELECT COUNT(*) FROM prompt_versions").fetchone()[0]
            tag_count = conn.execute("SELECT COUNT(*) FROM prompt_tags").fetchone()[0]
        return {
            "db_path": str(self.db_path),
            "prompt_count": prompt_count,
            "version_count": version_count,
            "tag_count": tag_count,
            "max_content_bytes": self.max_content_bytes,
            "security_mode_default": default_security_mode(),
        }

    def scan_prompt_security(
        self,
        *,
        content: str | None = None,
        name: str | None = None,
        ref: str | int | None = "HEAD",
        security_mode: str | None = None,
    ) -> dict[str, Any]:
        has_content = content is not None
        has_name = name is not None and name != ""
        if has_content == has_name:
            raise ValidationError("Provide exactly one of content or name")
        if content is not None:
            safe_content = self._validate_content(content)
            return {
                "source": {"type": "content"},
                "security": self._scan_security(safe_content, security_mode),
            }

        safe_name = self._validate_name(name or "")
        with self._connect() as conn:
            row = self._resolve_version(conn, safe_name, ref)
            source = _row_ref(row)
        return {
            "source": {"type": "stored_prompt", **source},
            "security": self._scan_security(row["content"], security_mode),
        }

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _head_row(self, conn: sqlite3.Connection, name: str) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT *
            FROM prompt_versions
            WHERE name = ?
            ORDER BY version DESC
            LIMIT 1
            """,
            (name,),
        ).fetchone()

    def _version_by_id(self, conn: sqlite3.Connection, version_id: int) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT * FROM prompt_versions WHERE id = ?",
            (version_id,),
        ).fetchone()

    def _prompt_exists(self, conn: sqlite3.Connection, name: str) -> bool:
        row = conn.execute(
            "SELECT 1 FROM prompt_versions WHERE name = ? LIMIT 1",
            (name,),
        ).fetchone()
        return row is not None

    def _resolve_version(
        self,
        conn: sqlite3.Connection,
        name: str,
        ref: str | int | None,
    ) -> sqlite3.Row:
        if ref is None:
            row = self._head_row(conn, name)
            return _require_version(row, name, ref)

        if isinstance(ref, int) and not isinstance(ref, bool):
            row = conn.execute(
                "SELECT * FROM prompt_versions WHERE name = ? AND version = ?",
                (name, ref),
            ).fetchone()
            return _require_version(row, name, ref)

        safe_ref = str(ref).strip()
        if safe_ref.lower() in {"", "head", "latest"}:
            row = self._head_row(conn, name)
            return _require_version(row, name, ref)

        if safe_ref.startswith("id:") and safe_ref[3:].isdigit():
            row = conn.execute(
                "SELECT * FROM prompt_versions WHERE name = ? AND id = ?",
                (name, int(safe_ref[3:])),
            ).fetchone()
            return _require_version(row, name, ref)

        if safe_ref.startswith("tag:"):
            safe_tag = self._validate_tag(safe_ref[4:])
            row = self._tag_row(conn, name, safe_tag)
            return _require_version(row, name, ref)

        version_ref = safe_ref[1:] if safe_ref.startswith("v") else safe_ref
        if version_ref.isdigit():
            row = conn.execute(
                "SELECT * FROM prompt_versions WHERE name = ? AND version = ?",
                (name, int(version_ref)),
            ).fetchone()
            return _require_version(row, name, ref)

        safe_tag = self._validate_tag(safe_ref)
        row = self._tag_row(conn, name, safe_tag)
        return _require_version(row, name, ref)

    def _tag_row(
        self,
        conn: sqlite3.Connection,
        name: str,
        tag: str,
    ) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT pv.*
            FROM prompt_tags pt
            JOIN prompt_versions pv ON pv.id = pt.version_id
            WHERE pt.name = ? AND pt.tag = ?
            """,
            (name, tag),
        ).fetchone()

    def _version_summary(
        self,
        conn: sqlite3.Connection,
        row: sqlite3.Row,
        *,
        created: bool | None = None,
        include_content: bool = False,
    ) -> dict[str, Any]:
        version = {
            "id": row["id"],
            "name": row["name"],
            "version": row["version"],
            "content_sha256": row["content_sha256"],
            "message": row["message"],
            "metadata": _json_loads_object(row["metadata_json"]),
            "created_at": row["created_at"],
            "tags": self._tags_for_version(conn, int(row["id"])),
        }
        if created is not None:
            version["created"] = created
        if include_content:
            version["content"] = row["content"]
        return version

    def _tags_for_version(self, conn: sqlite3.Connection, version_id: int) -> list[str]:
        rows = conn.execute(
            """
            SELECT tag
            FROM prompt_tags
            WHERE version_id = ?
            ORDER BY lower(tag)
            """,
            (version_id,),
        ).fetchall()
        return [row["tag"] for row in rows]

    def _validate_name(self, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError("Prompt name must be a string")
        name = value.strip()
        if not _NAME_RE.fullmatch(name):
            raise ValidationError(
                "Prompt name must start with a letter or number and contain only "
                "letters, numbers, '.', '_', '-', or '/'; max length is 128"
            )
        return name

    def _validate_tag(self, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError("Tag must be a string")
        tag = value.strip()
        if not _TAG_RE.fullmatch(tag):
            raise ValidationError(
                "Tag must start with a letter or number and contain only letters, "
                "numbers, '.', '_', '-', '+', or '/'; max length is 64"
            )
        return tag

    def _validate_content(self, value: str) -> str:
        if not isinstance(value, str):
            raise ValidationError("Prompt content must be a string")
        content_size = len(value.encode("utf-8"))
        if content_size > self.max_content_bytes:
            raise ValidationError(
                f"Prompt content is {content_size} bytes; limit is {self.max_content_bytes}"
            )
        return value

    def _validate_message(self, value: str | None) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValidationError("Message must be a string")
        message = value.strip()
        if len(message) > _MAX_MESSAGE_CHARS:
            raise ValidationError(f"Message must be at most {_MAX_MESSAGE_CHARS} characters")
        return message

    def _validate_metadata(self, value: dict[str, Any]) -> str:
        if not isinstance(value, dict):
            raise ValidationError("Metadata must be an object")
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError) as exc:
            raise ValidationError("Metadata must be JSON serializable") from exc
        if len(encoded.encode("utf-8")) > _MAX_METADATA_BYTES:
            raise ValidationError(f"Metadata must be at most {_MAX_METADATA_BYTES} bytes")
        return encoded

    def _scan_security(self, content: str, mode: str | None) -> dict[str, Any]:
        try:
            return scan_prompt_content(content, mode=mode)
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc


def _require_version(
    row: sqlite3.Row | None,
    name: str,
    ref: str | int | None,
) -> sqlite3.Row:
    if row is None:
        raise NotFoundError(f"Prompt '{name}' has no version for ref '{ref}'")
    return row


def _row_ref(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "version": row["version"],
        "content_sha256": row["content_sha256"],
        "created_at": row["created_at"],
    }


def _validate_limit(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError("Limit must be an integer")
    if value < 1 or value > 500:
        raise ValidationError("Limit must be between 1 and 500")
    return value


def _validate_offset(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError("Offset must be an integer")
    if value < 0:
        raise ValidationError("Offset must be >= 0")
    return value


def _validate_context_lines(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError("context_lines must be an integer")
    if value < 0 or value > 50:
        raise ValidationError("context_lines must be between 0 and 50")
    return value


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _json_loads_object(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError:
        return {}
    return decoded if isinstance(decoded, dict) else {}


def _security_block_message(report: dict[str, Any]) -> str:
    rule_ids = ", ".join(finding["rule_id"] for finding in report["findings"][:5])
    return (
        "Prompt blocked by security scan. "
        f"max_severity={report['max_severity']}; rules={rule_ids}. "
        "Use security_mode='warn' only for intentional testing."
    )
