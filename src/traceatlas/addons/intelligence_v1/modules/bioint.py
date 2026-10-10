"""Local review of supplied biological research metadata.

The uploaded BIOINT file was empty. This adapter checks record completeness;
it does not perform biological modeling, diagnosis, or experimental design.
"""
from collections import Counter


def analyze_bioint_manifest(manifest):
    records = manifest.get("research_records", [])
    if not isinstance(records, list) or len(records) > 500:
        raise ValueError("research_records must be an array of at most 500 records")
    seen, duplicates, observations, gaps = set(), [], [], []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise ValueError("Each research record must be an object")
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("Each research record requires a record_id")
        if record_id in seen:
            duplicates.append(record_id)
        seen.add(record_id)
        missing = [field for field in ("source_id", "publication_date", "method", "limitations")
                   if not record.get(field)]
        if missing:
            gaps.append({"record_id": record_id, "missing_metadata": missing})
        observations.append({"record_id": record_id, "source_id": record.get("source_id"),
                             "index": index, "metadata_complete": not missing,
                             "record_type": record.get("record_type", "UNKNOWN")})
    return {"case_id": manifest.get("case_id"), "status": "ANALYSIS_DRAFT",
            "observations": observations, "duplicate_record_ids": sorted(set(duplicates)),
            "record_type_counts": dict(Counter(row["record_type"] for row in observations)),
            "knowledge_gaps": gaps, "source_authenticity_verified": False,
            "clinical_or_biological_effect_verified": False, "network_calls": 0,
            "requires_human_review": True}
