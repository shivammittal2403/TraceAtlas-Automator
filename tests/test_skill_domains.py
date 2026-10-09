from traceatlas.skills import DOMAINS, FAMILIES, SkillDefinition, SkillRegistry, resolve_domain
from traceatlas.skills.domains import domains_for_family, search_domains


def test_universal_intelligence_taxonomy_is_complete_and_unique():
    assert len(DOMAINS) == 140
    assert len({row.domain_id for row in DOMAINS}) == 140
    assert set(row.family for row in DOMAINS) == set(FAMILIES)
    assert sum(len(domains_for_family(family)) for family in FAMILIES) == 140


def test_domain_aliases_resolve_without_claiming_execution():
    assert resolve_domain("OSINT").domain_id == "osint"
    assert resolve_domain("Social Media Intelligence").domain_id == "socmint"
    assert resolve_domain("retrieval-augmented-generation").domain_id == "rag"
    assert resolve_domain("airint").domain_id == "aviint"
    assert resolve_domain("Dark-Web Intelligence").sensitive is True


def test_domain_search_supports_employee_discovery():
    matches = search_domains("scam fraud payment", limit=20)
    ids = {row.domain_id for row in matches}
    assert "scamint" in ids
    assert "fraudint" in ids
    assert "payment-int" in ids


def test_skill_registry_separates_catalogue_from_execution():
    skill = SkillDefinition(
        skill_id="web.dorking",
        version="1",
        family="web_socmint",
        domains=("osint", "webint"),
        description="Generate bounded reproducible public-web research queries.",
        input_types=("text", "domain"),
        output_types=("observations", "queries"),
        required_capabilities=("public_web_search",),
        offline_capable=True,
        implementation_state="procedure",
    )
    registry = SkillRegistry((skill,))
    assert registry.get("web.dorking") == skill
    assert registry.search(domains=("webint",)) == (skill,)
    assert registry.describe()["skills"][0]["implementation_state"] == "procedure"
