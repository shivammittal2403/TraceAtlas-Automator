"""Operator-key-backed custody checkpoints for evidence ledgers.

The key must come from a separately protected provider. The file adapter is
portable and detects local ledger rewrites while its receipt and key remain
outside the attacker's control; it is not immutable storage or rollback proof.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Callable, Protocol


class LedgerAnchor(Protocol):
    """Trust-boundary contract consumed by EvidenceStore."""

    def assert_external_to(self, workspace_root: Path) -> None: ...

    def publish(self, case_id: str, entry_count: int, ledger_head: str) -> dict[str, Any]: ...

    def current_receipt(self, case_id: str) -> dict[str, Any] | None: ...

    def verify(
        self, case_id: str, entry_count: int, ledger_head: str,
        receipt: dict[str, Any] | None = None,
    ) -> bool: ...


def configured_ledger_anchor(workspace_root: Path) -> tuple[LedgerAnchor | None, bool]:
    """Resolve opt-in CLI/application configuration without logging key bytes.

    Supply the hex key through an operator secret manager at process startup.
    Setting the anchor directory enables required anchoring for that workspace.
    """
    required_value = os.environ.get("TRACEATLAS_EVIDENCE_ANCHOR_REQUIRED", "").strip().lower()
    if required_value not in {"", "0", "false", "no", "1", "true", "yes"}:
        raise ValueError("TRACEATLAS_EVIDENCE_ANCHOR_REQUIRED must be a boolean value")
    required = required_value in {"1", "true", "yes"}
    directory = os.environ.get("TRACEATLAS_EVIDENCE_ANCHOR_DIR", "").strip()
    key_hex = os.environ.get("TRACEATLAS_EVIDENCE_ANCHOR_KEY_HEX", "").strip()
    key_id = os.environ.get("TRACEATLAS_EVIDENCE_ANCHOR_KEY_ID", "operator-hmac-v1").strip()
    if not directory:
        if required:
            raise ValueError("Required evidence anchoring is configured without an anchor directory")
        return None, False
    if not key_hex:
        raise ValueError("Evidence anchor directory is configured without an operator key")
    try:
        key = bytes.fromhex(key_hex)
    except ValueError:
        raise ValueError("Evidence anchor key must be hexadecimal") from None
    if len(key) < 32:
        raise ValueError("Evidence anchor key must contain at least 32 bytes")
    anchor = HmacFileLedgerAnchor(
        Path(directory), workspace_root, lambda key=key: key, key_id=key_id,
    )
    return anchor, True


class HmacFileLedgerAnchor:
    """Store signed ledger-head receipts outside the evidence workspace.

    `key_resolver` should obtain a 256-bit-or-stronger key from an operator
    secret manager or another independent trust boundary. This adapter stores
    receipts atomically and enforces forward movement while its receipt file is
    available. It cannot guarantee freshness if an attacker can roll back the
    receipt file, so production qualification still requires an append-only or
    monotonic external provider.
    """

    SCHEMA = "traceatlas-ledger-anchor/v1"

    def __init__(
        self,
        root: Path,
        workspace_root: Path,
        key_resolver: Callable[[], bytes],
        *,
        key_id: str,
    ):
        if not key_id or len(key_id) > 128:
            raise ValueError("Invalid anchor key identifier")
        if not callable(key_resolver):
            raise ValueError("Anchor key resolver is required")
        self.root = root.resolve()
        self.workspace_root = workspace_root.resolve()
        self.key_resolver = key_resolver
        self.key_id = key_id
        self.assert_external_to(self.workspace_root)
        self.root.mkdir(parents=True, exist_ok=True)

    def assert_external_to(self, workspace_root: Path) -> None:
        workspace = workspace_root.resolve()
        if self.root == workspace or self.root.is_relative_to(workspace):
            raise ValueError("Ledger anchor storage must be outside the evidence workspace")

    def _path(self, case_id: str) -> Path:
        if not case_id or len(case_id) > 256:
            raise ValueError("Invalid anchor case identifier")
        name = hashlib.sha256(case_id.encode("utf-8")).hexdigest()
        return self.root / f"{name}.json"

    def _key(self) -> bytes:
        value = self.key_resolver()
        if not isinstance(value, bytes) or len(value) < 32:
            raise ValueError("Anchor key must contain at least 32 bytes")
        return value

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> bytes:
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def current_receipt(self, case_id: str) -> dict[str, Any] | None:
        path = self._path(case_id)
        if not path.exists():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("Ledger anchor receipt is invalid")
        return value

    def verify(
        self, case_id: str, entry_count: int, ledger_head: str,
        receipt: dict[str, Any] | None = None,
    ) -> bool:
        try:
            value = receipt if receipt is not None else self.current_receipt(case_id)
            if not isinstance(value, dict) or set(value) != {
                "schema", "case_id", "entry_count", "ledger_head", "key_id", "signature",
            }:
                return False
            if (
                value["schema"] != self.SCHEMA
                or value["case_id"] != case_id
                or value["entry_count"] != entry_count
                or value["ledger_head"] != ledger_head
                or value["key_id"] != self.key_id
                or isinstance(value["entry_count"], bool)
                or not isinstance(value["entry_count"], int)
                or not isinstance(value["ledger_head"], str)
                or len(value["ledger_head"]) != 64
                or not isinstance(value["signature"], str)
                or len(value["signature"]) != 64
            ):
                return False
            unsigned = {key: value[key] for key in value if key != "signature"}
            expected = hmac.new(self._key(), self._canonical(unsigned), hashlib.sha256).hexdigest()
            return hmac.compare_digest(value["signature"], expected)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return False

    def publish(self, case_id: str, entry_count: int, ledger_head: str) -> dict[str, Any]:
        if isinstance(entry_count, bool) or not isinstance(entry_count, int) or entry_count < 1:
            raise ValueError("Anchor entry count must be a positive integer")
        if (
            not isinstance(ledger_head, str) or len(ledger_head) != 64
            or any(character not in "0123456789abcdef" for character in ledger_head)
        ):
            raise ValueError("Invalid ledger head digest")
        previous = self.current_receipt(case_id)
        if previous is not None:
            if not self.verify(case_id, previous.get("entry_count"), previous.get("ledger_head"), previous):
                raise ValueError("Existing ledger anchor receipt failed verification")
            previous_count = previous["entry_count"]
            if entry_count < previous_count:
                raise ValueError("Ledger anchor cannot move backwards")
            if entry_count == previous_count:
                if ledger_head != previous["ledger_head"]:
                    raise ValueError("Ledger anchor cannot replace a checkpoint at the same sequence")
                return previous
        unsigned = {
            "schema": self.SCHEMA,
            "case_id": case_id,
            "entry_count": entry_count,
            "ledger_head": ledger_head,
            "key_id": self.key_id,
        }
        receipt = {
            **unsigned,
            "signature": hmac.new(self._key(), self._canonical(unsigned), hashlib.sha256).hexdigest(),
        }
        destination = self._path(case_id)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".anchor-", dir=self.root)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_name, destination)
        except Exception:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise
        return receipt

