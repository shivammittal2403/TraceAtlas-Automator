"""Keep cached evidence and background results attached to their input case."""
import json


def fingerprint(payload):
    return json.dumps({k: v for k, v in payload.items() if k != "generated_at"},
                      sort_keys=True, ensure_ascii=False, default=str)


def invalidate(panel, parsed_factory=None):
    state = panel.__dict__
    state["_work_revision"] = state.get("_work_revision", 0) + 1
    state["last_result"] = {}
    for key in ("analyzed_audio", "extracted_segments", "analyzed_videos",
                "extracted_frames", "analyzed_images", "analyzed_files"):
        if key in state:
            state[key] = []
    if parsed_factory is not None:
        state["parsed"] = parsed_factory()


def sync_inputs(panel, payload, parsed_factory=None):
    signature = fingerprint(payload)
    state = panel.__dict__
    old = state.get("_input_signature")
    if old is not None and old != signature:
        invalidate(panel, parsed_factory)
    state["_input_signature"] = signature


def begin_work(panel):
    state = panel.__dict__
    state["_work_revision"] = state.get("_work_revision", 0) + 1
    return state["_work_revision"]


def apply_result(panel, token, payload, callback, cache=None):
    # Called on the UI thread. collect_payload invalidates old case caches.
    current = panel.collect_payload()
    if token != panel.__dict__.get("_work_revision") or fingerprint(current) != fingerprint(payload):
        return False
    for key, value in (cache or {}).items():
        setattr(panel, key, value)
    callback()
    return True
