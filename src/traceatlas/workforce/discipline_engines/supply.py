"""Supply-chain, vendor and transport analysis over supplied records."""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
import heapq
import math
import re

from .common import AnalysisContext
from .discovery import _interval, _strong_components
from .media import number, _point, _distance


def _text(value):
    return value.strip() if isinstance(value, str) else ""


def _instant(value):
    start, _, precision = _interval(value)
    if precision != "instant":
        raise ValueError("Operation times require timezone-aware timestamps")
    return start


def _id(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Identifier requires nonempty text")
    return value.strip()


def supplychainint(ctx: AnalysisContext):
    networks = []
    for record in ctx.records:
        nodes, edges = record.data.get("nodes"), record.data.get("edges")
        if not isinstance(nodes, list) or not isinstance(edges, list):
            ctx.issue(record.record_id, "invalid_supply_graph", "nodes and edges require arrays.")
            continue
        counts, metadata = defaultdict(int), {}
        for node in nodes:
            if not isinstance(node, dict) or not _text(node.get("id")):
                ctx.issue(record.record_id, "invalid_supply_node", "Supply node requires an identifier.")
                continue
            key = node["id"].strip()
            counts[key] += 1
            metadata[key] = node
        ambiguous = {key for key, count in counts.items() if count > 1}
        for key in sorted(ambiguous):
            ctx.issue(record.record_id, "ambiguous_supply_node", "Repeated node ID is excluded: " + key)
        valid = set(metadata) - ambiguous
        adjacency, suppliers, normalized = defaultdict(list), defaultdict(list), []
        for edge in edges:
            try:
                if not isinstance(edge, dict):
                    raise ValueError("Edge requires an object")
                left, right = _id(edge.get("from")), _id(edge.get("to"))
                relation = edge.get("relation", "depends_on")
                if not isinstance(relation, str) or relation not in {"depends_on", "supplies"}:
                    raise ValueError("Unsupported supply relation")
                if left not in valid or right not in valid:
                    raise ValueError("Edge node is missing or ambiguous")
                consumer, dependency = (left, right) if relation == "depends_on" else (right, left)
                lead = number(edge["lead_time_days"], "lead_time_days", 0) if "lead_time_days" in edge else None
                share = number(edge["share"], "share", 0, 1) if "share" in edge else None
                item = {"consumer": consumer, "dependency": dependency, "relation": relation,
                        "lead_time_days": lead, "share": share}
                if any(old["consumer"] == consumer and old["dependency"] == dependency and
                       old["relation"] == relation for old in normalized):
                    ctx.issue(record.record_id, "duplicate_supply_edge",
                              "Repeated supply links cannot multiply dependency or share counts.")
                    continue
                normalized.append(item)
                adjacency[consumer].append((dependency, lead))
                if relation == "supplies":
                    suppliers[consumer].append((dependency, share))
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_supply_edge", str(exc))
        cycles = _strong_components(valid, [(row["consumer"], row["dependency"]) for row in normalized])
        roots = record.data.get("root_ids", sorted(valid))
        if not isinstance(roots, list) or any(not isinstance(root, str) or root not in valid for root in roots):
            ctx.issue(record.record_id, "invalid_supply_roots", "root_ids must reference unambiguous nodes.")
            roots = []
        cached = {}
        def lead_time(node, active=()):
            if node in cached:
                return cached[node]
            if node in active:
                return None
            branches = []
            for dependency, lead in adjacency[node]:
                tail = lead_time(dependency, active + (node,))
                if lead is None or tail is None:
                    return None
                try:
                    branches.append(number(lead + tail, "derived lead time", 0))
                except ValueError:
                    return None
            result = max(branches) if branches else 0.0
            cached[node] = result
            return result
        roots_out = []
        for root in sorted(set(roots)):
            tiers, queue = {root: 0}, deque([root])
            while queue:
                current = queue.popleft()
                for dependency, _lead in adjacency[current]:
                    if dependency not in tiers:
                        tiers[dependency] = tiers[current] + 1
                        queue.append(dependency)
            path = lead_time(root)
            if path is None:
                ctx.issue(record.record_id, "supply_lead_time_unknown",
                          "Cycles or missing edge durations prevent a complete critical-path duration.")
            roots_out.append({"root_id": root, "upstream_tiers": tiers, "critical_path_days": path})
        concentrations = []
        for consumer, rows in sorted(suppliers.items()):
            complete = all(share is not None for _, share in rows)
            total = math.fsum(share for _, share in rows if share is not None)
            normalized_shares = complete and math.isclose(total, 1.0, abs_tol=1e-9)
            concentrations.append({"consumer": consumer, "reported_supplier_ids": sorted({key for key, _ in rows}),
                "reported_single_source": len({key for key, _ in rows}) == 1,
                "declared_share_sum": total if complete else None,
                "hhi": math.fsum(share * share for _, share in rows) if normalized_shares else None,
                "supplier_universe_verified": False})
        item = {"record_id": record.record_id, "nodes": sorted(valid), "edges": normalized,
                "cycles": cycles, "roots": roots_out, "supplier_concentration": concentrations,
                "ambiguous_node_ids": sorted(ambiguous)}
        networks.append(item)
        ctx.finding("supply_dependency_analysis", "Computed upstream tiers, duration bounds and supplied supplier concentration.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"supply_graphs": len(networks), "cycles": sum(len(row["cycles"]) for row in networks)},
        artifacts={"supply_graphs": networks},
        limitations=("The supplied graph may omit suppliers; critical paths model declared edge durations, not operational guarantees.",),
    )


def vendorint(ctx: AnalysisContext):
    vendors = []
    for record in ctx.records:
        vendor_id, deliveries = _text(record.data.get("vendor_id")), record.data.get("deliveries")
        if not vendor_id or not isinstance(deliveries, list):
            ctx.issue(record.record_id, "invalid_vendor_deliveries", "Record requires vendor_id and deliveries.")
            continue
        ids = defaultdict(int)
        for row in deliveries:
            if isinstance(row, dict) and _text(row.get("delivery_id")):
                ids[row["delivery_id"].strip()] += 1
        accepted, pending = [], 0
        unit_totals = defaultdict(lambda: {"ordered": 0.0, "fulfilled_known": 0.0, "unknown_delivered_count": 0})
        for row in deliveries:
            try:
                if not isinstance(row, dict):
                    raise ValueError("Delivery requires an object")
                delivery_id = _id(row.get("delivery_id"))
                if ids[delivery_id] != 1:
                    raise ValueError("Duplicate delivery IDs require explicit revision resolution")
                ordered = number(row.get("ordered_quantity"), "ordered_quantity", 0.000000001)
                delivered = number(row["delivered_quantity"], "delivered_quantity", 0) if "delivered_quantity" in row else None
                unit = _id(row.get("unit"))
                _promised_start, promised_end, _ = _interval(row.get("promised_at"))
                actual = row.get("delivered_at")
                if actual is not None:
                    actual_start, actual_end, _ = _interval(actual)
                    on_time = True if actual_end <= promised_end else False if actual_start >= promised_end else None
                else:
                    actual_start = actual_end = on_time = None
                totals = unit_totals[unit]
                next_ordered = number(totals["ordered"] + ordered, "ordered quantity total", 0)
                next_fulfilled = number(totals["fulfilled_known"] + min(delivered, ordered),
                                        "fulfilled quantity total", 0) if delivered is not None else totals["fulfilled_known"]
                in_full = delivered >= ordered if delivered is not None else None
                item = {"delivery_id": delivery_id, "on_time": on_time, "in_full": in_full,
                        "otif": in_full and on_time if in_full is not None and on_time is not None else None}
                if actual is None:
                    pending += 1
                    item["status"] = "DELIVERY_TIME_UNKNOWN"
                else:
                    item["lateness_days_interval"] = [
                        max(0, (actual_start - promised_end).total_seconds() / 86400),
                        max(0, (actual_end - promised_end).total_seconds() / 86400)]
                if delivered is None:
                    ctx.issue(record.record_id, "vendor_delivered_quantity_unknown",
                              "Missing delivered quantity is not zero fulfillment.")
                accepted.append(item)
                totals["ordered"], totals["fulfilled_known"] = next_ordered, next_fulfilled
                totals["unknown_delivered_count"] += delivered is None
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_vendor_delivery", str(exc))
        assessed = [row for row in accepted if row["on_time"] is not None]
        otif_assessed = [row for row in accepted if row["otif"] is not None]
        item = {"record_id": record.record_id, "vendor_id": vendor_id, "deliveries": accepted,
                "pending_or_unknown_delivery_times": pending,
                "on_time_rate": sum(row["on_time"] for row in assessed) / len(assessed) if assessed else None,
                "otif_rate": sum(row["otif"] for row in otif_assessed) / len(otif_assessed) if otif_assessed else None,
                "fill_rates_by_unit": {unit: {**totals, "fill_rate":
                    totals["fulfilled_known"] / totals["ordered"] if totals["ordered"] and
                    not totals["unknown_delivered_count"] else None}
                    for unit, totals in sorted(unit_totals.items())}}
        vendors.append(item)
        ctx.finding("vendor_delivery_performance", "Calculated supplied on-time/in-full and unit-separated fill rates.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"vendor_manifests": len(vendors)}, artifacts={"vendors": vendors},
        limitations=("Delivery outcomes and promised times are supplied assertions; metrics do not independently qualify a vendor.",),
    )


_TRANSITIONS = {
    "CREATED": {"PICKED_UP"}, "PICKED_UP": {"IN_TRANSIT", "AT_HUB"},
    "IN_TRANSIT": {"AT_HUB", "OUT_FOR_DELIVERY", "DELIVERED", "EXCEPTION"},
    "AT_HUB": {"IN_TRANSIT", "OUT_FOR_DELIVERY", "EXCEPTION"},
    "OUT_FOR_DELIVERY": {"DELIVERED", "EXCEPTION"},
    "EXCEPTION": {"IN_TRANSIT", "RETURNED", "DELIVERED"},
    "DELIVERED": {"RETURNED"}, "RETURNED": set(),
}


def logisticsint(ctx: AnalysisContext):
    shipments = []
    for record in ctx.records:
        shipment_id, events, legs = _text(record.data.get("shipment_id")), record.data.get("events"), record.data.get("legs", [])
        if not shipment_id or not isinstance(events, list) or not isinstance(legs, list):
            ctx.issue(record.record_id, "invalid_shipment", "Shipment requires shipment_id, events and optional legs arrays.")
            continue
        counts = defaultdict(int)
        for event in events:
            if isinstance(event, dict) and _text(event.get("event_id")):
                counts[event["event_id"].strip()] += 1
        parsed = []
        for event in events:
            try:
                if not isinstance(event, dict):
                    raise ValueError("Shipment event requires an object")
                event_id, status = _id(event.get("event_id")), event.get("status")
                if counts[event_id] != 1:
                    raise ValueError("Duplicate event IDs are ambiguous")
                if not isinstance(status, str) or status not in _TRANSITIONS:
                    raise ValueError("Unsupported shipment status")
                parsed.append({"event_id": event_id, "status": status,
                               "time": _instant(event.get("time")).isoformat(),
                               "location_id": _text(event.get("location_id")) or None})
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_shipment_event", str(exc))
        parsed.sort(key=lambda row: (row["time"], row["event_id"]))
        unusual = []
        for before, after in zip(parsed, parsed[1:]):
            if before["time"] == after["time"] and before["status"] != after["status"]:
                ctx.issue(record.record_id, "simultaneous_shipment_statuses",
                          "Different statuses at the same time cannot establish transition order.")
                continue
            if after["status"] != before["status"] and after["status"] not in _TRANSITIONS[before["status"]]:
                unusual.append({"from_event": before["event_id"], "to_event": after["event_id"],
                                "from_status": before["status"], "to_status": after["status"]})
        route, gaps = [], []
        for index, leg in enumerate(legs):
            try:
                if not isinstance(leg, dict):
                    raise ValueError("Leg requires an object")
                origin, destination = _id(leg.get("origin")), _id(leg.get("destination"))
                departure, arrival = _instant(leg.get("departed_at")), _instant(leg.get("arrived_at"))
                if arrival < departure:
                    raise ValueError("Leg arrives before departure")
                route.append({"leg_index": index, "origin": origin, "destination": destination,
                              "departed_at": departure.isoformat(), "arrived_at": arrival.isoformat(),
                              "duration_seconds": (arrival - departure).total_seconds()})
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_shipment_leg", str(exc))
        route.sort(key=lambda row: (row["departed_at"], row["leg_index"]))
        for before, after in zip(route, route[1:]):
            if before["destination"] != after["origin"] or before["arrived_at"] > after["departed_at"]:
                gaps.append({"before_leg": before["leg_index"], "after_leg": after["leg_index"],
                             "location_gap": before["destination"] != after["origin"],
                             "time_overlap": before["arrived_at"] > after["departed_at"]})
        item = {"record_id": record.record_id, "shipment_id": shipment_id, "events": parsed,
                "workflow_transition_gaps": unusual, "legs": route, "route_continuity_gaps": gaps,
                "known_transit_seconds": math.fsum(leg["duration_seconds"] for leg in route)}
        shipments.append(item)
        ctx.finding("shipment_continuity_analysis", "Analyzed supplied shipment transitions and route continuity.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"shipments": len(shipments), "route_gaps": sum(
            len(row["route_continuity_gaps"]) for row in shipments)},
        artifacts={"shipments": shipments},
        limitations=("Missing intermediate events can explain workflow gaps; no current location or actual delivery is inferred.",),
    )


def transportint(ctx: AnalysisContext):
    networks = []
    for record in ctx.records:
        stops, services, journey = record.data.get("stops"), record.data.get("services"), record.data.get("journey")
        if not isinstance(stops, list) or not isinstance(services, list) or not isinstance(journey, dict):
            ctx.issue(record.record_id, "invalid_transport_network", "Record requires stops, services and journey.")
            continue
        stop_counts = defaultdict(int)
        for stop in stops:
            if isinstance(stop, dict) and _text(stop.get("stop_id")):
                stop_counts[stop["stop_id"].strip()] += 1
            else:
                ctx.issue(record.record_id, "invalid_transport_stop", "Stop requires a nonempty stop_id.")
        valid_stops = {key for key, count in stop_counts.items() if count == 1}
        if any(count > 1 for count in stop_counts.values()):
            ctx.issue(record.record_id, "ambiguous_transport_stop", "Duplicate stop IDs are excluded from journey routing.")
        departures, accepted = defaultdict(list), []
        for index, service in enumerate(services):
            try:
                if not isinstance(service, dict):
                    raise ValueError("Service requires an object")
                service_id, origin, destination = _id(service.get("service_id")), _id(service.get("from")), _id(service.get("to"))
                if origin not in valid_stops or destination not in valid_stops:
                    raise ValueError("Service endpoint is unknown")
                if service.get("cancelled") is True:
                    continue
                departure, arrival = _instant(service.get("departure")), _instant(service.get("arrival"))
                if arrival < departure:
                    raise ValueError("Service arrives before departure")
                trip = {"index": index, "service_id": service_id, "from": origin, "to": destination,
                        "departure": departure, "arrival": arrival}
                departures[origin].append(trip)
                accepted.append(trip)
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_transport_service", str(exc))
        try:
            origin, destination = _id(journey.get("origin")), _id(journey.get("destination"))
            earliest = _instant(journey.get("earliest_departure"))
            transfer = number(journey.get("minimum_transfer_minutes", 0), "minimum_transfer_minutes", 0, 10080) * 60
            if origin not in valid_stops or destination not in valid_stops:
                raise ValueError("Journey endpoint is unknown")
        except (ValueError, TypeError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_transport_journey", str(exc))
            continue
        # State includes the previous service so staying on the same service does
        # not incorrectly incur the transfer-time requirement.
        queue, best, counter = [(earliest, 0, origin, "", [])], {(origin, ""): earliest}, 0
        winner = None
        while queue:
            time, _, stop, last_service, path = heapq.heappop(queue)
            if best.get((stop, last_service)) != time:
                continue
            if stop == destination:
                winner = (time, path)
                break
            for trip in departures[stop]:
                wait = 0 if not path or last_service == trip["service_id"] else transfer
                if trip["departure"] < time + timedelta(seconds=wait):
                    continue
                state = (trip["to"], trip["service_id"])
                if state in best and best[state] <= trip["arrival"]:
                    continue
                best[state] = trip["arrival"]
                counter += 1
                heapq.heappush(queue, (trip["arrival"], counter, trip["to"], trip["service_id"], path + [trip]))
        path = []
        if winner:
            for trip in winner[1]:
                path.append({key: value.isoformat() if isinstance(value, datetime) else value
                             for key, value in trip.items()})
        item = {"record_id": record.record_id, "accepted_services": len(accepted),
                "journey_status": "JOURNEY_IN_SUPPLIED_TIMETABLE" if winner else "NO_JOURNEY_IN_SUPPLIED_TIMETABLE",
                "arrival": winner[0].isoformat() if winner else None, "legs": path,
                "elapsed_seconds": (winner[0] - earliest).total_seconds() if winner else None}
        networks.append(item)
        ctx.finding("multimodal_timetable_journey", "Computed earliest arrival subject to supplied services and transfer times.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"transport_networks": len(networks)}, artifacts={"journeys": networks},
        limitations=("A supplied timetable journey is not a live operating service, booking or exhaustive route search.",),
    )


def _imo(value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{7}", value):
        raise ValueError("IMO requires seven digits as text")
    if sum(int(digit) * weight for digit, weight in zip(value[:6], range(7, 1, -1))) % 10 != int(value[-1]):
        raise ValueError("IMO check digit mismatch")
    return value


def maritimeint(ctx: AnalysisContext):
    tracks = []
    for record in ctx.records:
        vessel, positions = record.data.get("vessel"), record.data.get("positions")
        if not isinstance(vessel, dict) or not isinstance(positions, list):
            ctx.issue(record.record_id, "invalid_maritime_track", "Track requires vessel and positions.")
            continue
        try:
            imo = _imo(vessel["imo"]) if "imo" in vessel else None
            mmsi = vessel.get("mmsi")
            if mmsi is not None and (not isinstance(mmsi, str) or not re.fullmatch(r"\d{9}", mmsi)):
                raise ValueError("MMSI requires nine digits as text")
            if imo is None and mmsi is None:
                raise ValueError("Vessel requires IMO or MMSI")
            gap_hours = number(record.data.get("max_gap_hours", 6), "max_gap_hours", 0.000001, 8760)
            speed_limit = number(record.data.get("max_plausible_speed_knots", 80), "speed threshold", 0.000001)
        except (ValueError, TypeError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_vessel_identifier", str(exc))
            continue
        parsed = []
        for index, position in enumerate(positions):
            try:
                if not isinstance(position, dict):
                    raise ValueError("Position requires an object")
                stamp = _instant(position.get("timestamp"))
                point = _point(position)
                if stamp > ctx.as_of:
                    raise ValueError("Position follows as_of")
                sog = None
                if "raw_sog" in position:
                    raw = position["raw_sog"]
                    if isinstance(raw, bool) or not isinstance(raw, int) or not 0 <= raw <= 1023:
                        raise ValueError("raw_sog requires AIS ten-bit speed")
                    sog = None if raw == 1023 else raw / 10
                elif position.get("sog_knots") is not None:
                    sog = number(position["sog_knots"], "sog_knots", 0)
                parsed.append({"timestamp": stamp, "point": point, "sog_knots": sog, "supplied_index": index})
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_maritime_position", str(exc))
        parsed.sort(key=lambda row: (row["timestamp"], row["supplied_index"]))
        segments = []
        for before, after in zip(parsed, parsed[1:]):
            elapsed = (after["timestamp"] - before["timestamp"]).total_seconds()
            distance = _distance(before["point"], after["point"])
            if elapsed == 0:
                if distance > 0:
                    ctx.issue(record.record_id, "simultaneous_maritime_position_conflict",
                              "Different locations at the same timestamp cannot define a trajectory.")
                continue
            speed = distance / elapsed * 1.9438444924406
            segments.append({"from_time": before["timestamp"].isoformat(),
                             "to_time": after["timestamp"].isoformat(), "elapsed_seconds": elapsed,
                             "straight_line_distance_m": distance, "minimum_average_speed_knots": speed,
                             "observation_gap": elapsed > gap_hours * 3600,
                             "speed_exceeds_supplied_threshold": speed > speed_limit})
        item = {"record_id": record.record_id, "imo": imo, "mmsi": mmsi,
                "positions": [{"timestamp": row["timestamp"].isoformat(), **row["point"],
                               "sog_knots": row["sog_knots"]} for row in parsed],
                "segments": segments, "live_location_verified": False}
        tracks.append(item)
        ctx.finding("maritime_track_consistency", "Validated identifiers and computed gap-aware supplied position geometry.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"maritime_tracks": len(tracks), "observation_gaps": sum(
            segment["observation_gap"] for track in tracks for segment in track["segments"])},
        artifacts={"tracks": tracks},
        limitations=("Straight-line movement is a lower bound between supplied observations; identifiers and AIS reports do not verify vessel identity or live position.",),
    )


def aviationint(ctx: AnalysisContext):
    aircraft_results = []
    phases = (("taxi_out_seconds", "off_block", "takeoff"),
              ("airborne_seconds", "takeoff", "landing"),
              ("taxi_in_seconds", "landing", "on_block"),
              ("block_seconds", "off_block", "on_block"))
    for record in ctx.records:
        aircraft, flights = record.data.get("aircraft"), record.data.get("flights")
        if not isinstance(aircraft, dict) or not isinstance(flights, list):
            ctx.issue(record.record_id, "invalid_aviation_record", "Record requires aircraft and flights.")
            continue
        icao = aircraft.get("icao24")
        registration = _text(aircraft.get("registration")).upper()
        if icao is not None and (not isinstance(icao, str) or not re.fullmatch(r"[0-9a-fA-F]{6}", icao)):
            ctx.issue(record.record_id, "invalid_icao24", "ICAO24 requires six hexadecimal digits.")
            continue
        if registration and not re.fullmatch(r"[A-Z0-9-]{3,12}", registration):
            ctx.issue(record.record_id, "invalid_aircraft_registration", "Registration syntax is unsupported.")
            continue
        if icao is None and not registration:
            ctx.issue(record.record_id, "missing_aircraft_identifier", "Aircraft requires ICAO24 or registration.")
            continue
        outputs, ids = [], defaultdict(int)
        for flight in flights:
            if isinstance(flight, dict) and _text(flight.get("flight_id")):
                ids[flight["flight_id"].strip()] += 1
        for flight in flights:
            try:
                if not isinstance(flight, dict):
                    raise ValueError("Flight requires an object")
                flight_id = _id(flight.get("flight_id"))
                if ids[flight_id] != 1:
                    raise ValueError("Duplicate flight identifiers require dated/revision disambiguation")
                times = {key: _instant(flight[key]) for key in
                         ("off_block", "takeoff", "landing", "on_block", "scheduled_departure", "scheduled_arrival")
                         if flight.get(key) is not None}
                item = {"flight_id": flight_id, "phase_times": {key: value.isoformat() for key, value in times.items()},
                        "cancelled_asserted": flight.get("cancelled") is True}
                if item["cancelled_asserted"] and any(key in times for key in ("takeoff", "landing")):
                    ctx.issue(record.record_id, "cancelled_flight_has_operation_times",
                              "Cancellation assertion conflicts with supplied flight-phase times.")
                for metric, first, last in phases:
                    item[metric] = None
                    if first in times and last in times:
                        seconds = (times[last] - times[first]).total_seconds()
                        if seconds < 0:
                            ctx.issue(record.record_id, "reversed_flight_phase",
                                      "Supplied flight phase ends before it starts.")
                        else:
                            item[metric] = seconds
                item["departure_delay_seconds"] = (times["off_block"] - times["scheduled_departure"]).total_seconds() if {
                    "off_block", "scheduled_departure"}.issubset(times) else None
                item["arrival_delay_seconds"] = (times["on_block"] - times["scheduled_arrival"]).total_seconds() if {
                    "on_block", "scheduled_arrival"}.issubset(times) else None
                outputs.append(item)
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_flight_times", str(exc))
        result = {"record_id": record.record_id, "icao24": icao.lower() if isinstance(icao, str) else None,
                  "registration": registration or None, "flights": outputs, "aircraft_identity_verified": False}
        aircraft_results.append(result)
        ctx.finding("aviation_phase_timing", "Separated flight block, airborne and taxi durations from supplied timestamps.",
                    [record.record_id], data=result)
    return ctx.output(
        metrics={"aircraft_manifests": len(aircraft_results)}, artifacts={"aircraft": aircraft_results},
        limitations=("Aircraft identifiers may be reassigned; phase arithmetic does not verify operation, current position or registered ownership.",),
    )


def _rail_base(day, offset):
    if not isinstance(day, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day):
        raise ValueError("service_date requires YYYY-MM-DD")
    if not isinstance(offset, str) or not re.fullmatch(r"[+-]\d{2}:\d{2}", offset):
        raise ValueError("timezone_offset requires an explicit fixed UTC offset")
    hours, minutes = map(int, offset[1:].split(":"))
    if hours > 23 or minutes > 59:
        raise ValueError("Timezone offset is invalid")
    delta = timedelta(hours=hours, minutes=minutes) * (-1 if offset.startswith("-") else 1)
    return datetime.fromisoformat(day).replace(tzinfo=timezone(delta))


def _rail_time(base, value):
    if not isinstance(value, str) or not re.fullmatch(r"\d{1,3}:\d{2}:\d{2}", value):
        raise ValueError("Rail time requires service-day HH:MM:SS")
    hours, minutes, seconds = map(int, value.split(":"))
    if hours > 167 or minutes > 59 or seconds > 59:
        raise ValueError("Rail time is outside the supported service-week range")
    return base + timedelta(hours=hours, minutes=minutes, seconds=seconds)


def railint(ctx: AnalysisContext):
    trips = []
    for record in ctx.records:
        try:
            trip_id = _id(record.data.get("trip_id"))
            base = _rail_base(record.data.get("service_date"), record.data.get("timezone_offset"))
            stops = record.data.get("stops")
            if not isinstance(stops, list):
                raise ValueError("stops requires an array")
        except (ValueError, TypeError, OverflowError) as exc:
            ctx.issue(record.record_id, "invalid_rail_trip", str(exc))
            continue
        parsed, seen, invalid_sequence = [], set(), False
        for stop in stops:
            try:
                if not isinstance(stop, dict):
                    raise ValueError("Stop requires an object")
                stop_id, sequence = _id(stop.get("stop_id")), stop.get("sequence")
                if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
                    raise ValueError("Stop sequence requires a nonnegative integer")
                if sequence in seen:
                    invalid_sequence = True
                    ctx.issue(record.record_id, "duplicate_rail_stop_sequence", "Duplicate sequence values make timetable order ambiguous.")
                seen.add(sequence)
                arrival = _rail_time(base, stop["arrival"]) if stop.get("arrival") is not None else None
                departure = _rail_time(base, stop["departure"]) if stop.get("departure") is not None else None
                if arrival is None and departure is None:
                    raise ValueError("Stop requires arrival or departure")
                if arrival and departure and departure < arrival:
                    raise ValueError("Stop departure precedes arrival")
                distance = number(stop["distance_km"], "distance_km", 0) if "distance_km" in stop else None
                parsed.append({"stop_id": stop_id, "sequence": sequence, "arrival": arrival,
                               "departure": departure, "distance_km": distance})
            except (ValueError, TypeError, OverflowError) as exc:
                ctx.issue(record.record_id, "invalid_rail_stop", str(exc))
        parsed.sort(key=lambda row: row["sequence"])
        chronology_valid = not invalid_sequence
        for before, after in zip(parsed, parsed[1:]):
            leave, reach = before["departure"] or before["arrival"], after["arrival"] or after["departure"]
            if reach < leave:
                chronology_valid = False
                ctx.issue(record.record_id, "reversed_rail_leg", "Later stop precedes the prior stop's time.")
            if before["distance_km"] is not None and after["distance_km"] is not None and after["distance_km"] < before["distance_km"]:
                ctx.issue(record.record_id, "decreasing_rail_distance", "Cumulative distance decreases between ordered stops.")
        runtime = None
        if chronology_valid and parsed and parsed[0]["departure"] is not None and parsed[-1]["arrival"] is not None:
            runtime = (parsed[-1]["arrival"] - parsed[0]["departure"]).total_seconds()
        dwell = math.fsum((row["departure"] - row["arrival"]).total_seconds() for row in parsed
                         if row["arrival"] is not None and row["departure"] is not None)
        item = {"record_id": record.record_id, "trip_id": trip_id,
                "stops": [{key: value.isoformat() if isinstance(value, datetime) else value
                           for key, value in row.items()} for row in parsed],
                "timetable_chronology_valid": chronology_valid, "scheduled_runtime_seconds": runtime,
                "known_dwell_seconds": dwell,
                "stops_with_unknown_dwell": sum(row["arrival"] is None or row["departure"] is None for row in parsed)}
        trips.append(item)
        ctx.finding("rail_service_day_timetable", "Resolved rail service-day times beyond midnight and checked stop-order arithmetic.",
                    [record.record_id], data=item)
    return ctx.output(
        metrics={"rail_trips": len(trips)}, artifacts={"trips": trips},
        limitations=("Fixed-offset supplied schedules are not live train movements; daylight-saving rules require a separately qualified timezone source.",),
    )


HANDLERS = {"SUPPLYCHAININT": supplychainint, "VENDORINT": vendorint,
            "LOGISTICSINT": logisticsint, "TRANSPORTINT": transportint,
            "MARITIMEINT": maritimeint, "AVIATIONINT": aviationint, "RAILINT": railint}
