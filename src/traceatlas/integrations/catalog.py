from __future__ import annotations

import gzip
import hashlib
import html
import json
import re
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


SCRIPT_RE = re.compile(
    r'<script[^>]+id=["\']tool-data["\'][^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL
)
MARKDOWN_ROW_RE = re.compile(
    r"^\|\s*\[([^\]]+)\]\((https?://[^)\s]+)\)\s*\|\s*(.*?)\s*\|\s*$"
)
API_MEGA_CATEGORY_RE = re.compile(r"(?:^|/)([^/]+?)-apis-\d+/README\.md$", re.IGNORECASE)
TRACKING_QUERY_KEYS = frozenset({
    "fpr", "utm_campaign", "utm_content", "utm_medium", "utm_source", "utm_term",
})
MAX_ZIP_MEMBERS = 1_000
MAX_ZIP_MEMBER_BYTES = 16 * 1024 * 1024
MAX_ZIP_READ_BYTES = 64 * 1024 * 1024


class CatalogStore:
    def __init__(self, workspace: Path):
        self.path = workspace / "tool-catalog.json"

    @staticmethod
    def _read_source(path: Path) -> Any:
        if path.suffix.lower() == ".zip":
            return CatalogStore._read_markdown_zip(path)
        raw = path.read_bytes()
        if raw[:2] == b"\x1f\x8b" or path.suffix.lower() == ".gz":
            raw = gzip.decompress(raw)
        text = raw.decode("utf-8", errors="replace")
        if "<html" in text[:1000].lower() or path.suffix.lower() in {".html", ".htm"}:
            match = SCRIPT_RE.search(text)
            if not match:
                raise ValueError("HTML has no embedded tool-data JSON block")
            text = match.group(1).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Tool catalog is not valid JSON: {exc}") from exc

    @staticmethod
    def _read_markdown_zip(path: Path) -> list[dict[str, str]]:
        """Read catalog tables without extracting or trusting archive paths.

        API Mega List is a discovery directory rather than an executable plugin
        bundle. Only Markdown table metadata is accepted. Scripts, images and
        archive paths are ignored.
        """
        rows: list[dict[str, str]] = []
        total_read = 0
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > MAX_ZIP_MEMBERS:
                raise ValueError("Catalog ZIP has too many members")
            for member in members:
                name = member.filename.replace("\\", "/")
                match = API_MEGA_CATEGORY_RE.search(name)
                is_featured = "/00-featured-apis/" in name and name.endswith("/README.md")
                is_root = name.count("/") == 1 and name.endswith("/README.md")
                if not match and not is_featured and not is_root:
                    continue
                if member.is_dir() or member.file_size > MAX_ZIP_MEMBER_BYTES:
                    raise ValueError("Catalog ZIP contains an oversized Markdown member")
                total_read += member.file_size
                if total_read > MAX_ZIP_READ_BYTES:
                    raise ValueError("Catalog ZIP Markdown exceeds the import limit")
                category = (
                    match.group(1).replace("-", " ").title()
                    if match else "Featured APIs" if is_featured else "API Mega List"
                )
                text = archive.read(member).decode("utf-8", errors="replace")
                for line in text.splitlines():
                    if is_root and line.startswith("## "):
                        heading = re.sub(r"<[^>]+>", "", line[3:]).strip(" #📊🚀📚")
                        if heading:
                            category = heading
                    parsed = MARKDOWN_ROW_RE.match(line.strip())
                    if not parsed:
                        continue
                    title, url, description = parsed.groups()
                    rows.append({
                        "name": html.unescape(title).strip(),
                        "url": html.unescape(url).strip(),
                        "description": html.unescape(description).replace("<br>", " ").strip(),
                        "category": category,
                        "source": "cporter202/API-mega-list",
                        "tags": "catalog-only,execution-disabled,license-unverified",
                    })
        if not rows:
            raise ValueError("Catalog ZIP has no supported API Markdown table rows")
        return rows

    @staticmethod
    def _dedupe_key(url: str) -> str:
        parsed = urlparse(url)
        query = urlencode([
            (key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key.lower() not in TRACKING_QUERY_KEYS
        ])
        path = parsed.path.rstrip("/") or "/"
        return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", query, ""))

    @staticmethod
    def _normalize(item: Any) -> dict[str, str] | None:
        if not isinstance(item, dict):
            return None
        name = str(item.get("name") or item.get("title") or "").strip()
        url = str(item.get("url") or item.get("link") or "").strip()
        if not name or not url:
            return None
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        return {
            "name": name,
            "url": url,
            "description": str(item.get("desc") or item.get("description") or "").strip(),
            "category": str(item.get("cat") or item.get("category") or "Uncategorized").strip(),
            "source": str(item.get("src") or item.get("source") or "imported").strip(),
            "tags": str(item.get("raw") or item.get("tags") or "").strip(),
            "execution": "catalog-only",
            "execution_enabled_by_catalog": "false",
            "license_status": str(item.get("license_status") or "unverified").strip(),
        }

    def import_file(self, path: Path) -> dict[str, Any]:
        data = self._read_source(path)
        if isinstance(data, dict):
            for key in ("tools", "data", "items", "results"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if not isinstance(data, list):
            raise ValueError("Catalog must contain a JSON array of tools")
        items: dict[str, dict[str, str]] = {}
        rejected = 0
        duplicates = 0
        for raw in data:
            item = self._normalize(raw)
            if not item:
                rejected += 1
                continue
            key = self._dedupe_key(item["url"])
            if key in items:
                duplicates += 1
                categories = {
                    part.strip() for part in items[key]["category"].split(" | ") if part.strip()
                }
                categories.add(item["category"])
                items[key]["category"] = " | ".join(sorted(categories, key=str.lower))
                continue
            items[key] = item
        if not items:
            raise ValueError(
                "Catalog contains zero usable tools. The supplied recon.html has an empty "
                "embedded array and expects a separate remote recon-data.json.gz file."
            )
        ordered = sorted(items.values(), key=lambda row: (row["category"].lower(), row["name"].lower()))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(ordered, indent=2, ensure_ascii=False), encoding="utf-8")
        return {
            "imported": len(ordered),
            "duplicates": duplicates,
            "rejected": rejected,
            "execution_enabled": 0,
            "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "path": str(self.path),
        }

    def all(self) -> list[dict[str, str]]:
        if not self.path.exists():
            return []
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []

    def search(self, query: str = "", category: str | None = None, limit: int = 50) -> list[dict[str, str]]:
        query = query.strip().lower()
        results = []
        for item in self.all():
            categories = {part.strip().lower() for part in item["category"].split(" | ")}
            if category and category.lower() not in categories:
                continue
            haystack = " ".join(item.values()).lower()
            if query and query not in haystack:
                continue
            results.append(item)
            if len(results) >= max(1, min(limit, 500)):
                break
        return results

    def stats(self) -> dict[str, Any]:
        items = self.all()
        categories: dict[str, int] = {}
        sources: dict[str, int] = {}
        for item in items:
            for category in item["category"].split(" | "):
                categories[category] = categories.get(category, 0) + 1
            sources[item["source"]] = sources.get(item["source"], 0) + 1
        return {
            "tools": len(items), "categories": categories, "sources": sources,
            "execution_enabled": sum(
                item.get("execution_enabled_by_catalog") == "true" for item in items
            ),
            "catalog_path": str(self.path),
        }
