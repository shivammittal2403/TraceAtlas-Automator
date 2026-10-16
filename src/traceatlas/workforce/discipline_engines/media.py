"""Measurement, geographic, media and document analysis over supplied records."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
import hashlib
import json
import math
import re
from statistics import median

from .common import AnalysisContext
from .discovery import _interval

UNITS = {
    "m": ("length", 1.0, 0.0), "cm": ("length", 0.01, 0.0),
    "mm": ("length", 0.001, 0.0), "km": ("length", 1000.0, 0.0),
    "s": ("time", 1.0, 0.0), "ms": ("time", 0.001, 0.0),
    "us": ("time", 0.000001, 0.0), "Hz": ("frequency", 1.0, 0.0),
    "kHz": ("frequency", 1000.0, 0.0), "MHz": ("frequency", 1_000_000.0, 0.0),
    "GHz": ("frequency", 1_000_000_000.0, 0.0), "K": ("temperature", 1.0, 0.0),
    "C": ("temperature", 1.0, 273.15), "Pa": ("pressure", 1.0, 0.0),
    "kPa": ("pressure", 1000.0, 0.0), "V": ("voltage", 1.0, 0.0),
    "mV": ("voltage", 0.001, 0.0), "A": ("current", 1.0, 0.0),
    "kg": ("mass", 1.0, 0.0), "g": ("mass", 0.001, 0.0),
}
BASE_UNITS = {"length": "m", "time": "s", "frequency": "Hz", "temperature": "K",
              "pressure": "Pa", "voltage": "V", "current": "A", "mass": "kg"}


def number(value, name, lower=None, upper=None):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(name + " requires a number")
    try:
        value = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(name + " is not a finite representable number") from exc
    if not math.isfinite(value) or (lower is not None and value < lower) or (
        upper is not None and value > upper
    ):
        raise ValueError(name + " is outside its finite permitted range")
    return value


def _integer(value, name, lower, upper):
    if isinstance(value, bool) or not isinstance(value, int) or not lower <= value <= upper:
        raise ValueError(name + " requires a bounded integer")
    return value


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical_measurement(data):
    unit = data.get("unit")
    if not isinstance(unit, str) or unit not in UNITS:
        raise ValueError("Unsupported measurement unit")
    dimension, factor, base_offset = UNITS[unit]
    raw = number(data.get("value"), "value")
    calibration = data.get("calibration", {})
    if not isinstance(calibration, dict):
        raise ValueError("calibration requires an object")
    scale = number(calibration.get("scale", 1), "scale")
    offset = number(calibration.get("offset", 0), "offset")
    nominal = number((raw * scale + offset) * factor + base_offset, "normalized value")
    interval = None
    if data.get("uncertainty") is not None:
        uncertainty = number(data["uncertainty"], "uncertainty", 0)
        scale_u = number(calibration.get("scale_uncertainty", 0), "scale uncertainty", 0)
        offset_u = number(calibration.get("offset_uncertainty", 0), "offset uncertainty", 0)
        products = [(raw + dv * uncertainty) * (scale + ds * scale_u)
                    for dv in (-1, 1) for ds in (-1, 1)]
        interval = [
            number((min(products) + offset - offset_u) * factor + base_offset, "lower bound"),
            number((max(products) + offset + offset_u) * factor + base_offset, "upper bound"),
        ]
    return {"dimension": dimension, "unit": BASE_UNITS[dimension], "value": nominal,
            "uncertainty_interval": interval,
            "calibration_basis": "supplied_parameters" if calibration else "not_supplied"}


def masint(ctx: AnalysisContext):
    rows = []
    for record in ctx.records:
        try:
            result = canonical_measurement(record.data)
            reference = record.data.get("reference")
            if reference is not None:
                if not isinstance(reference, dict):
                    raise ValueError("reference requires an object")
                expected = canonical_measurement(reference)
                if result["dimension"] != expected["dimension"]:
                    raise ValueError("Measurement/reference dimensions differ")
                actual_range, expected_range = result["uncertainty_interval"], expected["uncertainty_interval"]
                result["reference_compatibility"] = (
                    "UNKNOWN_UNCERTAINTY" if actual_range is None or expected_range is None
                    else "INTERVALS_OVERLAP" if max(actual_range[0], expected_range[0]) <=
                    min(actual_range[1], expected_range[1]) else "INTERVALS_DISJOINT"
                )
                result["reference"] = expected
            if result["uncertainty_interval"] is None:
                ctx.issue(record.record_id, "measurement_uncertainty_unknown",
                          "A missing uncertainty is not zero measurement error.")
            result["record_id"] = record.record_id
            rows.append(result)
            ctx.finding("normalized_measurement", "Converted supplied measurements and propagated interval bounds.",
                        [record.record_id], data=result)
        except (ValueError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_measurement", str(exc))
    return ctx.output(
        metrics={"measurements": len(rows), "uncertainty_intervals": sum(
            row["uncertainty_interval"] is not None for row in rows)},
        artifacts={"measurements": rows},
        limitations=("Calibration and reference values are supplied assertions; physical source calibration is unverified.",),
    )


def _point(data):
    if not isinstance(data, dict):
        raise ValueError("Point requires a coordinate object")
    crs = data.get("crs", "EPSG:4326")
    if crs == "EPSG:4326":
        latitude = number(data.get("latitude"), "latitude", -90, 90)
        longitude = number(data.get("longitude"), "longitude", -180, 180)
    elif crs == "EPSG:3857":
        x = number(data.get("x"), "x", -20_037_508.35, 20_037_508.35)
        y = number(data.get("y"), "y", -20_037_508.35, 20_037_508.35)
        longitude = math.degrees(x / 6_378_137.0)
        latitude = math.degrees(2 * math.atan(math.exp(y / 6_378_137.0)) - math.pi / 2)
    else:
        raise ValueError("Only EPSG:4326 and EPSG:3857 are supported")
    return {"latitude": latitude, "longitude": longitude,
            "uncertainty_m": number(data.get("uncertainty_m", 0), "uncertainty_m", 0, 40_100_000)}


def _distance(a, b):
    p1, p2 = math.radians(a["latitude"]), math.radians(b["latitude"])
    dp, dl = p2 - p1, math.radians(b["longitude"] - a["longitude"])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 6_371_000 * 2 * math.asin(math.sqrt(min(1, max(0, h))))


def geoint(ctx: AnalysisContext):
    points = []
    for record in ctx.records:
        try:
            point = _point(record.data)
            result = {"record_id": record.record_id, "wgs84": point}
            if record.data.get("query_point") is not None:
                target = _point(record.data["query_point"])
                result["query_distance_m"] = _distance(point, target)
                error = point["uncertainty_m"] + target["uncertainty_m"]
                result["distance_interval_m"] = [
                    max(0, result["query_distance_m"] - error),
                    result["query_distance_m"] + error,
                ]
            fence = record.data.get("geofence")
            if fence is not None:
                if not isinstance(fence, dict) or not isinstance(fence.get("center"), dict):
                    raise ValueError("geofence requires a center point")
                center = _point(fence["center"])
                radius = number(fence.get("radius_m"), "radius_m", 0, 40_100_000)
                distance = _distance(point, center)
                uncertainty = point["uncertainty_m"] + center["uncertainty_m"]
                lower, upper = max(0, distance - uncertainty), distance + uncertainty
                result["geofence"] = {"distance_m": distance, "radius_m": radius,
                    "assessment": "INSIDE" if upper <= radius else
                    "OUTSIDE" if lower > radius else "INTERSECTS_UNCERTAINTY"}
            points.append(result)
            ctx.finding("geospatial_measurement", "Computed supplied coordinate transforms and geographic bounds.",
                        [record.record_id], data=result)
        except (ValueError, TypeError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_geospatial_record", str(exc))
    return ctx.output(
        metrics={"points": len(points)}, artifacts={"points": points},
        limitations=("Coordinates and uncertainty radii are supplied observations, not verified locations or identities.",),
    )


def image_features(data):
    pixels = data.get("pixels")
    if not isinstance(pixels, list) or not pixels or any(
        not isinstance(row, list) or not row for row in pixels
    ):
        raise ValueError("pixels requires a nonempty grayscale matrix")
    width = len(pixels[0])
    if any(len(row) != width for row in pixels):
        raise ValueError("Pixel rows must have equal width")
    pixels = [[number(value, "pixel", 0, 255) for value in row] for row in pixels]
    orientation = _integer(data.get("orientation", 1), "orientation", 1, 8)
    if orientation == 2:
        pixels = [row[::-1] for row in pixels]
    elif orientation == 3:
        pixels = [row[::-1] for row in pixels[::-1]]
    elif orientation == 4:
        pixels = pixels[::-1]
    elif orientation == 5:
        pixels = [list(row) for row in zip(*pixels)]
    elif orientation == 6:
        pixels = [list(row) for row in zip(*pixels[::-1])]
    elif orientation == 7:
        pixels = [list(row)[::-1] for row in zip(*pixels[::-1])]
    elif orientation == 8:
        pixels = [list(row) for row in zip(*pixels)][::-1]
    height, width = len(pixels), len(pixels[0])
    flat = [value for row in pixels for value in row]
    mean = math.fsum(value / len(flat) for value in flat)
    histogram = [0] * 16
    for value in flat:
        histogram[min(15, int(value) // 16)] += 1
    sample = [[pixels[min(height - 1, y * height // 8)][min(width - 1, x * width // 9)]
               for x in range(9)] for y in range(8)]
    bits = 0
    for row in sample:
        for left, right in zip(row, row[1:]):
            bits = (bits << 1) | int(left > right)
    return {"width": width, "height": height, "pixel_count": len(flat),
            "mean_intensity": mean,
            "standard_deviation": math.sqrt(math.fsum((value - mean) ** 2 / len(flat) for value in flat)),
            "histogram_16_bins": histogram, "dhash": f"{bits:016x}",
            "pixel_sha256": _sha(json.dumps(pixels, separators=(",", ":"))),
            "orientation_applied": orientation}


def imint(ctx: AnalysisContext):
    images, candidates = [], []
    for record in ctx.records:
        try:
            item = {"record_id": record.record_id, **image_features(record.data)}
            images.append(item)
            ctx.finding("image_pixel_features", "Computed grayscale image statistics and orientation-aware fingerprints.",
                        [record.record_id], data=item)
        except (ValueError, TypeError) as exc:
            ctx.issue(record.record_id, "invalid_image_pixels", str(exc))
    for index, a in enumerate(images):
        for b in images[index + 1:]:
            hamming = (int(a["dhash"], 16) ^ int(b["dhash"], 16)).bit_count()
            if a["pixel_sha256"] == b["pixel_sha256"] or hamming <= 5:
                item = {"left_record_id": a["record_id"], "right_record_id": b["record_id"],
                        "pixel_identical": a["pixel_sha256"] == b["pixel_sha256"],
                        "dhash_distance": hamming, "identity_or_authenticity_verified": False}
                candidates.append(item)
    if candidates:
        ctx.finding("visual_similarity_candidates", "Image fingerprints identify non-biometric similarity candidates.",
                    [row["record_id"] for row in images],
                    data={"candidates": candidates[:200], "candidate_count": len(candidates),
                          "truncated": len(candidates) > 200})
    return ctx.output(
        metrics={"images": len(images), "similarity_candidates": len(candidates)},
        artifacts={"images": images, "similarity_candidates": candidates[:200],
                   "similarity_candidates_truncated": len(candidates) > 200},
        limitations=("Small perceptual hashes can collide; uniform images are especially ambiguous. No object, person or authenticity identification is performed.",),
    )


def vidint(ctx: AnalysisContext):
    videos = []
    for record in ctx.records:
        frames = record.data.get("frames")
        if not isinstance(frames, list):
            ctx.issue(record.record_id, "invalid_video_frames", "frames requires an array.")
            continue
        try:
            duration = number(record.data["duration"], "duration", 0) if "duration" in record.data else None
            fps = number(record.data["fps"], "fps", 0.000001) if "fps" in record.data else None
        except ValueError as exc:
            ctx.issue(record.record_id, "invalid_video_metadata", str(exc))
            continue
        parsed = []
        for index, frame in enumerate(frames):
            try:
                if not isinstance(frame, dict):
                    raise ValueError("Frame requires an object")
                stamp = number(frame.get("timestamp"), "frame timestamp", 0)
                if duration is not None and stamp > duration:
                    raise ValueError("Frame follows declared video duration")
                if "pixels" in frame:
                    features = image_features(frame)
                    fingerprint, mean = features["dhash"], features["mean_intensity"]
                else:
                    fingerprint = frame.get("dhash")
                    if not isinstance(fingerprint, str) or not re.fullmatch(r"[0-9a-fA-F]{16}", fingerprint):
                        raise ValueError("Frame requires grayscale pixels or a 64-bit dhash")
                    fingerprint, mean = fingerprint.lower(), None
                parsed.append({"timestamp": stamp, "dhash": fingerprint, "mean": mean,
                               "supplied_index": index})
            except (ValueError, TypeError) as exc:
                ctx.issue(record.record_id, "invalid_video_frame", str(exc))
        if any(a["timestamp"] > b["timestamp"] for a, b in zip(parsed, parsed[1:])):
            ctx.issue(record.record_id, "nonmonotonic_frame_order",
                      "Frames were sorted by supplied timestamps; original order was nonmonotonic.")
        parsed.sort(key=lambda row: (row["timestamp"], row["supplied_index"]))
        scene_changes, repeats, intervals, gaps = [], [], [], []
        for a, b in zip(parsed, parsed[1:]):
            delta = b["timestamp"] - a["timestamp"]
            distance = (int(a["dhash"], 16) ^ int(b["dhash"], 16)).bit_count()
            if delta == 0:
                if a["dhash"] != b["dhash"]:
                    ctx.issue(record.record_id, "simultaneous_frame_conflict",
                              "Different frames at the same timestamp cannot establish sequence.")
                continue
            intervals.append(delta)
            mean_change = abs(a["mean"] - b["mean"]) if a["mean"] is not None and b["mean"] is not None else None
            if distance >= 16 or (mean_change is not None and mean_change >= 30):
                scene_changes.append({"at_seconds": b["timestamp"], "dhash_distance": distance,
                                      "mean_intensity_change": mean_change})
            if distance == 0:
                repeats.append([a["timestamp"], b["timestamp"]])
            if fps is not None and record.data.get("sampling") == "complete" and delta > 1.5 / fps:
                gaps.append({"from_seconds": a["timestamp"], "to_seconds": b["timestamp"],
                             "expected_interval_seconds": 1 / fps})
        item = {"record_id": record.record_id, "valid_frames": len(parsed),
                "declared_duration": duration, "median_observed_frame_interval": median(intervals) if intervals else None,
                "scene_change_candidates": scene_changes, "repeated_fingerprint_intervals": repeats,
                "gaps_in_declared_complete_sample": gaps}
        videos.append(item)
        ctx.finding("video_sequence_analysis", "Analyzed supplied frame timing, fingerprints and continuity.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"videos": len(videos), "scene_change_candidates": sum(
            len(row["scene_change_candidates"]) for row in videos)},
        artifacts={"videos": videos},
        limitations=("Frame sampling, timestamps and supplied hashes remain assertions; continuity gaps do not alone prove editing.",),
    )


def audint(ctx: AnalysisContext):
    audio = []
    for record in ctx.records:
        try:
            rate = _integer(record.data.get("sample_rate"), "sample_rate", 1, 1_000_000)
            channels = _integer(record.data.get("channels", 1), "channels", 1, 8)
            samples = record.data.get("samples")
            if not isinstance(samples, list) or not samples or len(samples) % channels:
                raise ValueError("samples requires complete nonempty interleaved frames")
            fmt = record.data.get("sample_format", "float")
            if fmt not in {"float", "pcm16"}:
                raise ValueError("sample_format supports float or pcm16")
            values = [number(value, "sample", -1 if fmt == "float" else -32768,
                             1 if fmt == "float" else 32767) /
                      (1 if fmt == "float" else 32768) for value in samples]
            threshold = number(record.data.get("silence_threshold", 0.01), "silence threshold", 0, 1)
            per_channel = []
            for channel in range(channels):
                series = values[channel::channels]
                per_channel.append({
                    "channel": channel, "rms": math.sqrt(math.fsum(value * value / len(series) for value in series)),
                    "peak": max(abs(value) for value in series),
                    "dc_offset": math.fsum(value / len(series) for value in series),
                    "zero_crossings": sum((a < 0 <= b) or (a >= 0 > b) for a, b in zip(series, series[1:])),
                    "clipped_samples": sum(abs(value) >= (1 if fmt == "float" else 32767 / 32768) for value in series),
                })
            frames = [values[index:index + channels] for index in range(0, len(values), channels)]
            silent = [all(abs(value) <= threshold for value in frame) for frame in frames]
            runs, start = [], None
            for index, is_silent in enumerate(silent + [False]):
                if is_silent and start is None:
                    start = index
                if not is_silent and start is not None:
                    runs.append({"start_seconds": start / rate, "end_seconds": index / rate})
                    start = None
            item = {"record_id": record.record_id, "sample_frames": len(frames),
                    "duration_seconds": len(frames) / rate, "channels": per_channel,
                    "silence_intervals": runs, "silent_frame_fraction": sum(silent) / len(silent)}
            audio.append(item)
            ctx.finding("audio_signal_statistics", "Calculated supplied PCM amplitude, clipping, crossing and silence statistics.",
                        [record.record_id], data=item)
        except (ValueError, TypeError) as exc:
            ctx.issue(record.record_id, "invalid_audio_samples", str(exc))
    return ctx.output(
        metrics={"audio_records": len(audio)}, artifacts={"audio": audio},
        limitations=("Signal statistics do not identify speakers, emotions or recording authenticity.",),
    )


_REFERENCE = re.compile(r"https?://[^\s<>]+|10\.\d{4,9}/[^\s<>]+", re.IGNORECASE)


def docint(ctx: AnalysisContext):
    documents = []
    for record in ctx.records:
        pages = record.data.get("pages")
        if pages is None and isinstance(record.data.get("text"), str):
            pages = [{"page_number": 1, "text": record.data["text"]}]
        if not isinstance(pages, list):
            ctx.issue(record.record_id, "invalid_document_pages", "Document requires pages or text.")
            continue
        positions, references, tables, seen, offset, words = [], [], [], set(), 0, Counter()
        hashes = []
        for index, page in enumerate(pages):
            try:
                if not isinstance(page, dict) or not isinstance(page.get("text"), str):
                    raise ValueError("Page requires text")
                page_number = _integer(page.get("page_number", index + 1), "page_number", 1, 1_000_000)
            except ValueError as exc:
                ctx.issue(record.record_id, "invalid_document_page", str(exc))
                continue
            if page_number in seen:
                ctx.issue(record.record_id, "duplicate_page_number",
                          "Duplicate page numbers remain distinct page-index locators.")
            seen.add(page_number)
            text = page["text"]
            hashes.append(text)
            positions.append({"page_index": index, "page_number": page_number,
                              "start_offset": offset, "end_offset": offset + len(text),
                              "text_sha256": _sha(text)})
            words.update(token.casefold() for token in re.findall(r"\w+", text, re.UNICODE))
            for match in _REFERENCE.finditer(text):
                references.append({"page_index": index, "page_number": page_number,
                                   "start": match.start(), "end": match.end(), "text": match.group()})
            page_tables = page.get("tables", [])
            if not isinstance(page_tables, list):
                ctx.issue(record.record_id, "invalid_document_tables", "tables requires an array.")
                page_tables = []
            for table_index, table in enumerate(page_tables):
                if not isinstance(table, dict):
                    ctx.issue(record.record_id, "invalid_document_table", "Table requires an object.")
                    continue
                headers, rows = table.get("headers"), table.get("rows")
                if not isinstance(headers, list) or not all(isinstance(key, str) for key in headers) or (
                    len(headers) != len(set(headers)) or not headers
                ) or not isinstance(rows, list):
                    ctx.issue(record.record_id, "invalid_document_table", "Table requires unique string headers and rows.")
                    continue
                good = [row for row in rows if isinstance(row, list) and len(row) == len(headers)]
                if len(good) != len(rows):
                    ctx.issue(record.record_id, "table_width_mismatch", "Malformed table rows were excluded and counted.")
                tables.append({"page_index": index, "page_number": page_number, "table_index": table_index,
                               "headers": headers, "valid_row_count": len(good),
                               "invalid_row_count": len(rows) - len(good),
                               "preview_rows": good[:50], "preview_truncated": len(good) > 50})
            offset += len(text) + 1
        item = {"record_id": record.record_id, "pages": positions, "page_count": len(positions),
                "document_text_sha256": _sha("\f".join(hashes)),
                "word_count": sum(words.values()), "top_terms": [
                    {"term": term, "count": count} for term, count in words.most_common(25)],
                "references": references[:200], "reference_count": len(references),
                "references_truncated": len(references) > 200, "tables": tables}
        documents.append(item)
        ctx.finding("document_content_index", "Indexed supplied document text, locators, references and tables.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"documents": len(documents), "references": sum(row["reference_count"] for row in documents)},
        artifacts={"documents": documents},
        limitations=("Page text and tables are supplied extraction results; source document rendering and authenticity are not verified.",),
    )


def metadataint(ctx: AnalysisContext):
    profiles = []
    created_keys = {"createdat", "createdate", "creationdate", "datetimeoriginal"}
    modified_keys = {"modifiedat", "modifydate", "modificationdate"}
    for record in ctx.records:
        metadata = record.data.get("metadata")
        if not isinstance(metadata, dict):
            ctx.issue(record.record_id, "invalid_metadata", "metadata requires an object.")
            continue
        flat = []
        def flatten(value, path=""):
            for key, item in value.items():
                name = path + "." + key if path else key
                if isinstance(item, dict):
                    flatten(item, name)
                else:
                    flat.append({"path": name, "value": item})
        flatten(metadata)
        created, modified = [], []
        for field in flat:
            key = re.sub(r"[^a-z0-9]", "", field["path"].split(".")[-1].casefold())
            if key in created_keys | modified_keys:
                try:
                    start, end, precision = _interval(field["value"])
                    field["normalized_time"] = {"start": start.isoformat(), "end_exclusive": end.isoformat(),
                                                "precision": precision}
                    (created if key in created_keys else modified).append((start, end, field["path"]))
                except (ValueError, OverflowError):
                    ctx.issue(record.record_id, "ambiguous_metadata_time",
                              "Metadata timestamp lacks a supported timezone or precision.")
        anomalies = [{"created_field": c[2], "modified_field": m[2]} for c in created for m in modified
                     if m[1] <= c[0]]
        item = {"record_id": record.record_id, "fields": flat,
                "modification_before_creation": anomalies, "authenticity_verified": False}
        if "content_text" in record.data:
            if not isinstance(record.data["content_text"], str):
                ctx.issue(record.record_id, "invalid_metadata_content", "content_text must be text.")
            else:
                computed = _sha(record.data["content_text"])
                declared = record.data.get("sha256")
                item["computed_sha256"] = computed
                item["declared_hash_matches"] = computed == declared.lower() if isinstance(declared, str) else None
                if declared is not None and not item["declared_hash_matches"]:
                    ctx.issue(record.record_id, "metadata_hash_mismatch",
                              "Supplied content bytes differ from the declared SHA-256.")
        profiles.append(item)
        ctx.finding("metadata_consistency", "Preserved metadata fields and checked local chronology/hash consistency.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"metadata_records": len(profiles), "chronology_anomalies": sum(
            len(row["modification_before_creation"]) for row in profiles)},
        artifacts={"metadata": profiles},
        limitations=("Metadata may be edited; locally consistent fields do not prove authorship, identity or authenticity.",),
    )


HANDLERS = {"MASINT": masint, "GEOINT": geoint, "IMINT": imint, "VIDINT": vidint,
            "AUDINT": audint, "DOCINT": docint, "METADATAINT": metadataint}
