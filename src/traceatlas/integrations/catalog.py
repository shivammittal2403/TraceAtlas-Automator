from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


SCRIPT_RE = re.compile(
    r'<script[^>]+id=["\']tool-data["\'][^>]*>(.*?)</script>', re.IGNORECASE | re.DOTALL
)


class CatalogStore:
    def __init__(self, workspace: Path):
        self.path = workspace / "tool-catalog.json"

    @staticmethod
    def _read_source(path: Path) -> Any:
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
        for raw in data:
            item = self._normalize(raw)
            if not item:
                rejected += 1
                continue
            key = item["url"].lower().rstrip("/")
            items[key] = item
        if not items:
            raise ValueError(
                "Catalog contains zero usable tools. The supplied recon.html has an empty "
                "embedded array and expects a separate remote recon-data.json.gz file."
            )
        ordered = sorted(items.values(), key=lambda row: (row["category"].lower(), row["name"].lower()))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(ordered, indent=2, ensure_ascii=False), encoding="utf-8")
        return {"imported": len(ordered), "rejected": rejected, "path": str(self.path)}

    def all(self) -> list[dict[str, str]]:
        if not self.path.exists():
            return []
        data = json.loads(self.path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []

    def search(self, query: str = "", category: str | None = None, limit: int = 50) -> list[dict[str, str]]:
        query = query.strip().lower()
        results = []
        for item in self.all():
            if category and item["category"].lower() != category.lower():
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
            categories[item["category"]] = categories.get(item["category"], 0) + 1
            sources[item["source"]] = sources.get(item["source"], 0) + 1
        return {"tools": len(items), "categories": categories, "sources": sources,
                "catalog_path": str(self.path)}

