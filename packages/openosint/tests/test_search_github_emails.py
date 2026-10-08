"""Regression coverage for GitHub commit-email domain filtering."""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from openosint.tools import search_github


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("candidate", "expected"),
    [
        pytest.param("alice@evilnoreply.github.com", {"alice@evilnoreply.github.com"}, id="lookalike-domain"),
        pytest.param("alice@evilusers.noreply.github.com", {"alice@evilusers.noreply.github.com"}, id="lookalike-users-domain"),
        pytest.param("alice@noreply.github.com", set(), id="legacy-noreply"),
        pytest.param("123+alice@users.noreply.github.com", set(), id="users-noreply"),
        pytest.param("alice@NOREPLY.GITHUB.COM", set(), id="uppercase-legacy-noreply"),
        pytest.param("123+alice@USERS.NOREPLY.GITHUB.COM", set(), id="uppercase-users-noreply"),
        pytest.param(None, set(), id="null-email"),
        pytest.param(42, set(), id="numeric-email"),
        pytest.param([], set(), id="list-email"),
        pytest.param({}, set(), id="object-email"),
        pytest.param("", set(), id="empty-email"),
        pytest.param("not-an-email", set(), id="missing-separator"),
        pytest.param("@example.com", set(), id="missing-local-part"),
        pytest.param("alice@", set(), id="missing-domain"),
    ],
)
async def test_commit_email_filter_uses_complete_case_insensitive_domain(
    monkeypatch: pytest.MonkeyPatch, candidate, expected: set[str]
) -> None:
    get = AsyncMock(return_value=[
        {"commit": {"author": {"email": candidate}}},
        {"commit": {"author": {"email": "later@example.org"}}},
    ])
    monkeypatch.setattr(search_github, "_get", get)
    session = object()
    emails = await search_github._discover_emails(session, "alice", [{"name": "fixture-repo"}])
    assert emails == expected | {"later@example.org"}
    get.assert_awaited_once_with(
        session, "https://api.github.com/repos/alice/fixture-repo/commits",
        params={"author": "alice", "per_page": 5},
    )
