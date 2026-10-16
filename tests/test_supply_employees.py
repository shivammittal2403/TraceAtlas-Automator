"""Nonempty supply and transport semantics through production contexts."""
import unittest

from traceatlas.workforce.discipline_engines.common import make_context
from traceatlas.workforce.discipline_engines.supply import HANDLERS


class SupplyEmployeesTests(unittest.TestCase):
    @staticmethod
    def record(identifier, data):
        return {"record_id": identifier, "source_id": "s1", "data": data}

    def analyze(self, label, records):
        payload = {"case_id": "case-test", "task_id": "task-test", "discipline": label,
                   "objective": "Analyze supplied records", "as_of": "2026-10-15T00:00:00Z",
                   "sources": [{"source_id": "s1", "uri": "urn:fixture:s1"}],
                   "records": records, "parameters": {}}
        result = HANDLERS[label](make_context(payload))
        for finding in result["findings"]:
            self.assertTrue(set(finding["record_ids"]).issubset({row["record_id"] for row in records}))
        return result

    @staticmethod
    def graph():
        return {"nodes": [{"id": name} for name in ("product", "component", "raw", "vendor-a", "vendor-b")],
                "root_ids": ["product"], "edges": [
                    {"from": "product", "to": "component", "lead_time_days": 2},
                    {"from": "component", "to": "raw", "lead_time_days": 3},
                    {"from": "vendor-a", "to": "component", "relation": "supplies", "lead_time_days": 1, "share": 0.6},
                    {"from": "vendor-b", "to": "component", "relation": "supplies", "lead_time_days": 1, "share": 0.4}]}

    def test_supply_tiers_critical_path_and_supplier_concentration(self):
        result = self.analyze("SUPPLYCHAININT", [self.record("r1", self.graph())])
        graph = result["artifacts"]["supply_graphs"][0]
        self.assertEqual(graph["roots"][0]["upstream_tiers"]["raw"], 2)
        self.assertEqual(graph["roots"][0]["critical_path_days"], 5)
        concentration = graph["supplier_concentration"][0]
        self.assertAlmostEqual(concentration["hhi"], 0.52)
        self.assertFalse(concentration["reported_single_source"])
        self.assertFalse(concentration["supplier_universe_verified"])

    def test_supply_cycles_and_missing_durations_do_not_become_zero_lead_time(self):
        result = self.analyze("SUPPLYCHAININT", [self.record("r1", {
            "nodes": [{"id": "a"}, {"id": "b"}], "root_ids": ["a"],
            "edges": [{"from": "a", "to": "b", "lead_time_days": 1},
                      {"from": "b", "to": "a", "lead_time_days": 1}]})])
        graph = result["artifacts"]["supply_graphs"][0]
        self.assertEqual(len(graph["cycles"]), 1)
        self.assertIsNone(graph["roots"][0]["critical_path_days"])
        missing = self.analyze("SUPPLYCHAININT", [self.record("r1", {
            "nodes": [{"id": "a"}, {"id": "b"}], "root_ids": ["a"],
            "edges": [{"from": "a", "to": "b"}]})])
        self.assertIsNone(missing["artifacts"]["supply_graphs"][0]["roots"][0]["critical_path_days"])

    def test_supply_derived_overflow_is_unknown_and_valid_neighbor_survives(self):
        huge = {"nodes": [{"id": name} for name in ("a", "b", "c")], "root_ids": ["a"],
                "edges": [{"from": "a", "to": "b", "lead_time_days": 1e308},
                          {"from": "b", "to": "c", "lead_time_days": 1e308}]}
        result = self.analyze("SUPPLYCHAININT", [self.record("r1", huge), self.record("r2", self.graph())])
        self.assertEqual(result["metrics"]["supply_graphs"], 2)
        self.assertIsNone(result["artifacts"]["supply_graphs"][0]["roots"][0]["critical_path_days"])
        self.assertEqual(result["artifacts"]["supply_graphs"][1]["roots"][0]["critical_path_days"], 5)

    @staticmethod
    def delivery(identifier, ordered, delivered, actual):
        return {"delivery_id": identifier, "ordered_quantity": ordered, "delivered_quantity": delivered,
                "unit": "pieces", "promised_at": "2026-10-10T12:00:00Z", "delivered_at": actual}

    def test_vendor_on_time_in_full_and_quantity_weighted_fill(self):
        result = self.analyze("VENDORINT", [self.record("r1", {"vendor_id": "v", "deliveries": [
            self.delivery("d1", 10, 10, "2026-10-10T12:00:00Z"),
            self.delivery("d2", 20, 15, "2026-10-11T12:00:00Z")]})])
        vendor = result["artifacts"]["vendors"][0]
        self.assertEqual(vendor["on_time_rate"], 0.5)
        self.assertEqual(vendor["otif_rate"], 0.5)
        self.assertAlmostEqual(vendor["fill_rates_by_unit"]["pieces"]["fill_rate"], 25 / 30)

    def test_vendor_missing_delivered_quantity_is_not_zero(self):
        result = self.analyze("VENDORINT", [self.record("r1", {"vendor_id": "v", "deliveries": [{
            "delivery_id": "d1", "ordered_quantity": 10, "unit": "pieces",
            "promised_at": "2026-10-10T12:00:00Z", "delivered_at": "2026-10-10T12:00:00Z"}]})])
        vendor = result["artifacts"]["vendors"][0]
        self.assertEqual(vendor["on_time_rate"], 1)
        self.assertIsNone(vendor["otif_rate"])
        self.assertIsNone(vendor["fill_rates_by_unit"]["pieces"]["fill_rate"])
        self.assertIsNone(vendor["deliveries"][0]["in_full"])

    def test_vendor_units_do_not_mix_and_duplicate_delivery_ids_do_not_overwrite(self):
        a = self.delivery("same", 10, 10, "2026-10-10T12:00:00Z")
        b = self.delivery("same", 10, 0, "2026-10-11T12:00:00Z")
        result = self.analyze("VENDORINT", [self.record("r1", {"vendor_id": "v", "deliveries": [a, b]})])
        self.assertEqual(result["artifacts"]["vendors"][0]["deliveries"], [])
        c = self.delivery("d1", 10, 10, "2026-10-10T12:00:00Z")
        d = {**self.delivery("d2", 20, 10, "2026-10-10T12:00:00Z"), "unit": "kg"}
        result = self.analyze("VENDORINT", [self.record("r1", {"vendor_id": "v", "deliveries": [c, d]})])
        rates = result["artifacts"]["vendors"][0]["fill_rates_by_unit"]
        self.assertEqual(rates["pieces"]["fill_rate"], 1)
        self.assertEqual(rates["kg"]["fill_rate"], 0.5)

    def test_logistics_route_continuity_and_transit_arithmetic(self):
        result = self.analyze("LOGISTICSINT", [self.record("r1", {"shipment_id": "shipment", "events": [
            {"event_id": "e1", "status": "CREATED", "time": "2026-10-14T00:00:00Z"},
            {"event_id": "e2", "status": "PICKED_UP", "time": "2026-10-14T00:10:00Z"},
            {"event_id": "e3", "status": "IN_TRANSIT", "time": "2026-10-14T00:20:00Z"},
            {"event_id": "e4", "status": "DELIVERED", "time": "2026-10-14T03:00:00Z"}],
            "legs": [{"origin": "a", "destination": "b", "departed_at": "2026-10-14T00:00:00Z",
                      "arrived_at": "2026-10-14T01:00:00Z"},
                     {"origin": "b", "destination": "c", "departed_at": "2026-10-14T02:00:00Z",
                      "arrived_at": "2026-10-14T03:00:00Z"}]})])
        shipment = result["artifacts"]["shipments"][0]
        self.assertEqual(shipment["known_transit_seconds"], 7200)
        self.assertEqual(shipment["route_continuity_gaps"], [])
        self.assertEqual(shipment["workflow_transition_gaps"], [])

    def test_logistics_location_gap_and_time_overlap_stay_explicit(self):
        result = self.analyze("LOGISTICSINT", [self.record("r1", {"shipment_id": "s", "events": [],
            "legs": [{"origin": "a", "destination": "b", "departed_at": "2026-10-14T10:00:00Z",
                      "arrived_at": "2026-10-14T12:00:00Z"},
                     {"origin": "c", "destination": "d", "departed_at": "2026-10-14T11:00:00Z",
                      "arrived_at": "2026-10-14T13:00:00Z"}]})])
        gap = result["artifacts"]["shipments"][0]["route_continuity_gaps"][0]
        self.assertTrue(gap["location_gap"])
        self.assertTrue(gap["time_overlap"])

    def test_logistics_duplicate_event_id_does_not_choose_first_status(self):
        result = self.analyze("LOGISTICSINT", [self.record("r1", {"shipment_id": "s", "events": [
            {"event_id": "same", "status": "CREATED", "time": "2026-10-14T00:00:00Z"},
            {"event_id": "same", "status": "DELIVERED", "time": "2026-10-14T01:00:00Z"}]})])
        self.assertEqual(result["artifacts"]["shipments"][0]["events"], [])
        self.assertIn("invalid_shipment_event", {row["code"] for row in result["issues"]})

    @staticmethod
    def timetable():
        return {"stops": [{"stop_id": name} for name in ("a", "b", "c")], "services": [
            {"service_id": "train", "from": "a", "to": "b", "departure": "2026-10-14T10:00:00Z",
             "arrival": "2026-10-14T11:00:00Z"},
            {"service_id": "bus-early", "from": "b", "to": "c", "departure": "2026-10-14T11:05:00Z",
             "arrival": "2026-10-14T11:30:00Z"},
            {"service_id": "bus-late", "from": "b", "to": "c", "departure": "2026-10-14T11:15:00Z",
             "arrival": "2026-10-14T12:00:00Z"}],
            "journey": {"origin": "a", "destination": "c", "earliest_departure": "2026-10-14T09:00:00Z",
                        "minimum_transfer_minutes": 10}}

    def test_transport_earliest_arrival_respects_transfer_time(self):
        result = self.analyze("TRANSPORTINT", [self.record("r1", self.timetable())])
        journey = result["artifacts"]["journeys"][0]
        self.assertEqual(journey["arrival"], "2026-10-14T12:00:00+00:00")
        self.assertEqual([row["service_id"] for row in journey["legs"]], ["train", "bus-late"])

    def test_transport_same_service_continuation_does_not_require_transfer(self):
        timetable = self.timetable()
        timetable["services"][1]["service_id"] = "train"
        result = self.analyze("TRANSPORTINT", [self.record("r1", timetable)])
        self.assertEqual(result["artifacts"]["journeys"][0]["arrival"], "2026-10-14T11:30:00+00:00")

    def test_transport_reversed_service_produces_no_supplied_journey(self):
        timetable = self.timetable()
        timetable["services"] = [{"service_id": "bad", "from": "a", "to": "c",
            "departure": "2026-10-14T12:00:00Z", "arrival": "2026-10-14T11:00:00Z"}]
        result = self.analyze("TRANSPORTINT", [self.record("r1", timetable)])
        self.assertEqual(result["artifacts"]["journeys"][0]["journey_status"], "NO_JOURNEY_IN_SUPPLIED_TIMETABLE")
        self.assertIn("invalid_transport_service", {row["code"] for row in result["issues"]})

    def test_transport_huge_transfer_and_duplicate_stop_are_isolated(self):
        bad = self.timetable()
        bad["journey"]["minimum_transfer_minutes"] = 1e308
        duplicate = self.timetable()
        duplicate["stops"].append({"stop_id": "a"})
        result = self.analyze("TRANSPORTINT", [
            self.record("r1", bad), self.record("r2", duplicate), self.record("r3", self.timetable())])
        self.assertEqual(result["metrics"]["transport_networks"], 1)
        self.assertEqual(result["artifacts"]["journeys"][0]["record_id"], "r3")

    def test_maritime_check_digit_antimeridian_and_ais_unknown_speed(self):
        result = self.analyze("MARITIMEINT", [self.record("r1", {
            "vessel": {"imo": "9074729", "mmsi": "234567890"}, "positions": [
                {"timestamp": "2026-10-14T00:00:00Z", "latitude": 0, "longitude": 179.9, "raw_sog": 1023},
                {"timestamp": "2026-10-14T01:00:00Z", "latitude": 0, "longitude": -179.9, "raw_sog": 120}]})])
        track = result["artifacts"]["tracks"][0]
        self.assertIsNone(track["positions"][0]["sog_knots"])
        self.assertEqual(track["positions"][1]["sog_knots"], 12)
        self.assertGreater(track["segments"][0]["minimum_average_speed_knots"], 10)
        self.assertLess(track["segments"][0]["minimum_average_speed_knots"], 13)
        self.assertFalse(track["live_location_verified"])

    def test_maritime_invalid_imo_does_not_contaminate_valid_neighbor(self):
        result = self.analyze("MARITIMEINT", [
            self.record("r1", {"vessel": {"imo": "9074728"}, "positions": []}),
            self.record("r2", {"vessel": {"imo": "9074729"}, "positions": [
                {"timestamp": "2026-10-14T00:00:00Z", "latitude": 0, "longitude": 0}]})])
        self.assertEqual(result["metrics"]["maritime_tracks"], 1)
        self.assertEqual(result["artifacts"]["tracks"][0]["record_id"], "r2")

    def test_maritime_gaps_and_simultaneous_conflicts_do_not_imply_live_positions(self):
        result = self.analyze("MARITIMEINT", [self.record("r1", {
            "vessel": {"imo": "9074729"}, "max_gap_hours": 6, "positions": [
                {"timestamp": "2026-10-14T00:00:00Z", "latitude": 0, "longitude": 0},
                {"timestamp": "2026-10-14T00:00:00Z", "latitude": 0, "longitude": 1},
                {"timestamp": "2026-10-14T12:00:00Z", "latitude": 0, "longitude": 2}]})])
        self.assertEqual(result["metrics"]["observation_gaps"], 1)
        self.assertIn("simultaneous_maritime_position_conflict", {row["code"] for row in result["issues"]})

    @staticmethod
    def flight():
        return {"flight_id": "f", "off_block": "2026-10-14T09:00:00Z",
                "takeoff": "2026-10-14T09:10:00Z", "landing": "2026-10-14T11:50:00Z",
                "on_block": "2026-10-14T12:00:00Z", "scheduled_departure": "2026-10-14T08:55:00Z",
                "scheduled_arrival": "2026-10-14T11:55:00Z"}

    def test_aviation_airborne_block_taxi_and_delay_are_distinct(self):
        result = self.analyze("AVIATIONINT", [self.record("r1", {
            "aircraft": {"icao24": "AbC123", "registration": "VT-ABC"}, "flights": [self.flight()]})])
        aircraft = result["artifacts"]["aircraft"][0]
        flight = aircraft["flights"][0]
        self.assertEqual(flight["taxi_out_seconds"], 600)
        self.assertEqual(flight["airborne_seconds"], 9600)
        self.assertEqual(flight["taxi_in_seconds"], 600)
        self.assertEqual(flight["block_seconds"], 10800)
        self.assertEqual(flight["departure_delay_seconds"], 300)
        self.assertEqual(flight["arrival_delay_seconds"], 300)
        self.assertEqual(aircraft["icao24"], "abc123")
        self.assertFalse(aircraft["aircraft_identity_verified"])

    def test_aviation_reversed_phase_is_unknown_and_cancellation_conflict_visible(self):
        flight = self.flight()
        flight.update({"landing": "2026-10-14T08:00:00Z", "cancelled": True})
        result = self.analyze("AVIATIONINT", [self.record("r1", {
            "aircraft": {"icao24": "abc123"}, "flights": [flight]})])
        self.assertIsNone(result["artifacts"]["aircraft"][0]["flights"][0]["airborne_seconds"])
        codes = {row["code"] for row in result["issues"]}
        self.assertIn("reversed_flight_phase", codes)
        self.assertIn("cancelled_flight_has_operation_times", codes)

    def test_aviation_invalid_identifier_is_isolated_from_valid_neighbor(self):
        result = self.analyze("AVIATIONINT", [
            self.record("r1", {"aircraft": {"icao24": "nothex"}, "flights": [self.flight()]}),
            self.record("r2", {"aircraft": {"icao24": "abc123"}, "flights": [self.flight()]})])
        self.assertEqual(result["metrics"]["aircraft_manifests"], 1)
        self.assertEqual(result["artifacts"]["aircraft"][0]["record_id"], "r2")

    @staticmethod
    def rail_trip():
        return {"trip_id": "rail", "service_date": "2026-10-13", "timezone_offset": "+05:30",
                "stops": [{"stop_id": "a", "sequence": 1, "departure": "23:50:00", "distance_km": 0},
                          {"stop_id": "b", "sequence": 2, "arrival": "24:10:00", "departure": "24:15:00", "distance_km": 20},
                          {"stop_id": "c", "sequence": 3, "arrival": "25:00:00", "distance_km": 50}]}

    def test_rail_service_day_beyond_midnight_preserves_date_and_dwell_unknowns(self):
        result = self.analyze("RAILINT", [self.record("r1", self.rail_trip())])
        trip = result["artifacts"]["trips"][0]
        self.assertEqual(trip["scheduled_runtime_seconds"], 4200)
        self.assertEqual(trip["known_dwell_seconds"], 300)
        self.assertEqual(trip["stops_with_unknown_dwell"], 2)
        self.assertEqual(trip["stops"][2]["arrival"], "2026-10-14T01:00:00+05:30")

    def test_rail_missing_timezone_and_reversed_stop_order_do_not_invent_times(self):
        no_timezone = self.rail_trip()
        del no_timezone["timezone_offset"]
        reversed_trip = self.rail_trip()
        reversed_trip["stops"][2]["arrival"] = "23:00:00"
        result = self.analyze("RAILINT", [
            self.record("r1", no_timezone), self.record("r2", reversed_trip)])
        self.assertEqual(result["metrics"]["rail_trips"], 1)
        trip = result["artifacts"]["trips"][0]
        self.assertFalse(trip["timetable_chronology_valid"])
        self.assertIsNone(trip["scheduled_runtime_seconds"])

    def test_rail_duplicate_sequence_and_decreasing_distance_remain_issues(self):
        trip = self.rail_trip()
        trip["stops"][2]["sequence"] = 2
        trip["stops"][2]["distance_km"] = 10
        result = self.analyze("RAILINT", [self.record("r1", trip)])
        item = result["artifacts"]["trips"][0]
        self.assertFalse(item["timetable_chronology_valid"])
        codes = {row["code"] for row in result["issues"]}
        self.assertIn("duplicate_rail_stop_sequence", codes)
        self.assertIn("decreasing_rail_distance", codes)


if __name__ == "__main__":
    unittest.main()
