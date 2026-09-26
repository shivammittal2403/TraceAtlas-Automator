"""Source-aware normalization for consented public social/code profiles."""

from __future__ import annotations

from typing import Any


def _first(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = mapping.get(key)
        if value not in (None, "", [], {}):
            return value
    return None


def _bounded_metrics(**values: Any) -> dict[str, int]:
    result: dict[str, int] = {}
    for key, value in values.items():
        if isinstance(value, bool):
            continue
        try:
            number = int(value)
        except (TypeError, ValueError):
            continue
        if 0 <= number <= 10**12:
            result[key] = number
    return result


def normalize_social_profile(source: str, record: Any) -> dict[str, Any] | None:
    """Map official public profile responses into one non-inferential contract.

    The source response remains available as the sanitized observation. This
    compact view exists for cross-source review and never asserts that two
    matching handles belong to the same person.
    """
    if not isinstance(record, dict):
        return None
    profile: dict[str, Any]
    if source == "github":
        profile = {
            "handle": _first(record, "login"), "display_name": _first(record, "name"),
            "profile_url": _first(record, "html_url"), "biography": _first(record, "bio"),
            "organisation": _first(record, "company"), "location_label": _first(record, "location"),
            "website": _first(record, "blog"), "created_at": _first(record, "created_at"),
            "metrics": _bounded_metrics(
                followers=record.get("followers"), following=record.get("following"),
                public_repositories=record.get("public_repos"), public_gists=record.get("public_gists"),
            ),
        }
    elif source == "gitlab":
        profile = {
            "handle": _first(record, "username"), "display_name": _first(record, "name"),
            "profile_url": _first(record, "web_url"), "biography": _first(record, "bio"),
            "organisation": _first(record, "organization"),
            "location_label": _first(record, "location"),
            "website": _first(record, "website_url"), "created_at": _first(record, "created_at"),
            "metrics": _bounded_metrics(followers=record.get("followers"), following=record.get("following")),
        }
    elif source == "bluesky":
        profile = {
            "handle": _first(record, "handle"), "display_name": _first(record, "displayName"),
            "profile_url": f"https://bsky.app/profile/{record['handle']}" if record.get("handle") else None,
            "biography": _first(record, "description"), "created_at": _first(record, "createdAt"),
            "metrics": _bounded_metrics(
                followers=record.get("followersCount"), following=record.get("followsCount"),
                posts=record.get("postsCount"),
            ),
        }
    elif source == "hackernews":
        submitted = record.get("submitted")
        profile = {
            "handle": _first(record, "id"), "display_name": None,
            "profile_url": f"https://news.ycombinator.com/user?id={record['id']}" if record.get("id") else None,
            "biography": _first(record, "about"), "created_at": _first(record, "created"),
            "metrics": _bounded_metrics(
                karma=record.get("karma"),
                public_submissions=len(submitted) if isinstance(submitted, list) else None,
            ),
        }
    else:
        return None
    return {
        "contract_version": "1.0", "source": source,
        **{key: value for key, value in profile.items() if value not in (None, "", {}, [])},
        "identity_warning": "A matching handle or profile attribute is not proof of common identity.",
    }
