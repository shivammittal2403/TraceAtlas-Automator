"""Search all supplied integration candidates without pretending they are live."""
import json
import re
from functools import lru_cache
from importlib.resources import files


@lru_cache(maxsize=1)
def _register():
    return json.loads(files("traceatlas.employee.data").joinpath("tool_register.json").read_text(encoding="utf-8"))


def tool_candidates(query: str = "", limit: int = 20) -> dict:
    if not isinstance(query, str) or len(query) > 1000 or not 1 <= limit <= 200:
        raise ValueError("Invalid tool catalog query or limit")
    terms = set(re.findall(r"[\w-]+", query.casefold()))
    register = _register()
    rows = []
    for entry in register["entries"]:
        if entry["proposed_mode"] == "ALIAS":
            continue
        words = set(re.findall(r"[\w-]+", " ".join(str(entry.get(k, "")) for k in (
            "display_name", "group", "decision_and_next_action")).casefold()))
        score = len(terms & words)
        if terms and not score:
            continue
        rows.append({"id": entry["canonical_id"], "name": entry["display_name"],
                     "url": entry["candidate_url"], "route": entry["proposed_mode"],
                     "verification": entry["verification"], "next_action": entry["decision_and_next_action"],
                     "release_gate": entry["release_gate"], "score": score,
                     "execution_enabled_by_catalog": False})
    rows.sort(key=lambda r: (-r["score"], r["id"]))
    return {"as_of": register["as_of"], "input_entries": register["raw_entries"],
            "canonical_candidates": register["canonical_candidate_records"], "matches": rows[:limit],
            "total_matches": len(rows), "note": "Planning candidates, not a count of working integrations."}
