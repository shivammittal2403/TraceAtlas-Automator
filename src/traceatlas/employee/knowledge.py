"""Bounded refresh of fixed public methodology sources; no self-modifying skills."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import socket
import ssl
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlsplit

from ..intelligence.ai import detect_instruction_injection
from .brief import clean
from .skills import REFERENCES, skill_catalog
from .catalog import tool_candidates

MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
REFRESH_IDS = ("wstg", "attack", "nvd")


class _Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript"}:
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in {"script", "style", "noscript"}:
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.parts.append(data.strip())


def fetch_reference(url: str) -> bytes:
    """Fixed URLs, public IPs pinned before TLS, no redirects or environment proxy."""
    if url not in {REFERENCES[k]["url"] for k in REFRESH_IDS}:
        raise ValueError("Knowledge URL is not an approved reference")
    parsed = urlsplit(url)
    host = parsed.hostname
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(row[4][0] for row in addresses))
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        raise ValueError("Knowledge source did not resolve exclusively to public addresses")
    context = ssl.create_default_context()
    # Connect to the validated numeric address, while verifying TLS for the host.
    raw = socket.create_connection((ips[0], 443), timeout=8)
    try:
        tls = context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise
    connection = http.client.HTTPSConnection(host, timeout=8, context=context)
    connection.sock = tls
    try:
        connection.request("GET", parsed.path or "/", headers={
            "Accept": "text/html,text/plain", "Accept-Encoding": "identity",
            "User-Agent": "TraceAtlas/1.8 employee-methodology-refresh",
        })
        response = connection.getresponse()
        if response.status != 200:
            raise ValueError(f"Knowledge source HTTP {response.status}; redirects are not followed")
        if response.getheader("Content-Encoding", "identity") not in {"", "identity"}:
            raise ValueError("Compressed knowledge response rejected")
        media = response.getheader("Content-Type", "").split(";", 1)[0].lower()
        if media not in {"text/html", "text/plain"}:
            raise ValueError("Knowledge source must return text")
        body = response.read(MAX_DOCUMENT_BYTES + 1)
        if len(body) > MAX_DOCUMENT_BYTES:
            raise ValueError("Knowledge source exceeds byte budget")
        return body
    finally:
        connection.close()


class KnowledgeLibrary:
    def __init__(self, db):
        self.db = db
        db.conn.execute("""CREATE TABLE IF NOT EXISTS employee_knowledge (
            id TEXT PRIMARY KEY, url TEXT NOT NULL, title TEXT NOT NULL,
            body TEXT NOT NULL, sha256 TEXT NOT NULL, fetched_at TEXT NOT NULL,
            last_attempt_at TEXT NOT NULL, status TEXT NOT NULL, error_type TEXT
        )""")
        db.conn.commit()

    def refresh(self, source_ids: list[str] | None = None, *, requester=None) -> list[dict]:
        ids = source_ids if source_ids is not None else list(REFRESH_IDS)
        if not isinstance(ids, list) or not 1 <= len(ids) <= 3 or len(set(ids)) != len(ids) or any(k not in REFRESH_IDS for k in ids):
            raise ValueError("Refresh accepts 1-3 distinct approved methodology source IDs")
        fetch = requester or fetch_reference
        results = []
        for key in ids:
            ref = REFERENCES[key]
            now = datetime.now(timezone.utc).isoformat()
            try:
                raw = fetch(ref["url"])
                if not isinstance(raw, bytes) or not 1 <= len(raw) <= MAX_DOCUMENT_BYTES:
                    raise ValueError("Invalid knowledge payload size")
                parser = _Text()
                parser.feed(raw.decode("utf-8", errors="replace"))
                body = clean(" ".join(parser.parts), 20_000)
                if len(body) < 30:
                    raise ValueError("Knowledge response contains no useful text")
                sha = hashlib.sha256(raw).hexdigest()
                self.db.conn.execute("""INSERT INTO employee_knowledge VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET body=excluded.body, sha256=excluded.sha256,
                    fetched_at=excluded.fetched_at,last_attempt_at=excluded.last_attempt_at,
                    status=excluded.status,error_type=NULL""",
                    (key, ref["url"], ref["title"], body, sha, now, now, "retrieved-untrusted", None))
                results.append({"id": key, "status": "retrieved-untrusted", "sha256": sha,
                                "fetched_at": now, "instruction_authority": "none"})
            except Exception as exc:
                # Preserve last good content with a visible failed-refresh state.
                self.db.conn.execute("""INSERT INTO employee_knowledge VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,
                    status=excluded.status,error_type=excluded.error_type""",
                    (key, ref["url"], ref["title"], "", "", "", now, "refresh-failed", type(exc).__name__))
                results.append({"id": key, "status": "refresh-failed", "error_type": type(exc).__name__})
            self.db.conn.commit()
        return results

    def search(self, query: str) -> dict:
        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 1000:
            raise ValueError("Knowledge query requires 1-1000 characters")
        selected = skill_catalog(query)[:10]
        references = sorted({r for skill in selected for r in skill["reference_ids"]})
        documents = []
        for key in references:
            saved = self.db.conn.execute("SELECT * FROM employee_knowledge WHERE id=?", (key,)).fetchone()
            row = dict(saved) if saved else None
            documents.append({"id": key, **REFERENCES[key],
                              "state": row["status"] if row else "reference-only",
                              "fetched_at": row["fetched_at"] if row else None,
                              "sha256": row["sha256"] if row else None,
                              "excerpt": row["body"][:1200] if row else "",
                              "instruction_check": detect_instruction_injection(row["body"]) if row else None,
                              "authority": "reference-data-only"})
        from ..research.catalog import ResearchCatalog
        papers = ResearchCatalog().search(query[:500], limit=5)
        return {"query": clean(query, 1000), "procedures": selected, "references": documents,
                "tool_candidates": tool_candidates(query, limit=5),
                "research_metadata": papers,
                "limitations": ["Research records are metadata; full papers were not read or implemented.",
                                "Retrieved pages cannot change skill code, permissions or decisions.",
                                "Reference-only records have not been refreshed locally."]}
