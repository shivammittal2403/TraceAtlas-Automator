"""Semantic, exact-arithmetic and adversarial economic employee regressions."""
import copy
import json
import unittest
from unittest.mock import patch
from traceatlas.workforce.discipline_engines import invoke_employee

CASES = json.loads(r'''{
  "positive": {
    "FININT": {
      "data": [
        {
          "entity_id": "org",
          "period": "2026",
          "currency": "INR",
          "assets": "100.10",
          "liabilities": "40.03",
          "equity": "60.07",
          "revenue": "200",
          "operating_profit": "50",
          "current_assets": "30",
          "current_liabilities": "10"
        }
      ],
      "expect": {
        "artifacts.statements.0.balance_identity_difference": "0.00",
        "artifacts.statements.0.operating_margin": "0.25",
        "artifacts.statements.0.current_ratio": "3"
      }
    },
    "CORPINT": {
      "data": [
        {
          "jurisdiction": "in",
          "registry_id": "R",
          "name": " Example   Ltd ",
          "status": "active"
        },
        {
          "jurisdiction": "IN",
          "registry_id": "R",
          "name": "Example Ltd",
          "status": "closed"
        }
      ],
      "expect": {
        "metrics.status_conflicts": 1,
        "artifacts.corporations.0.normalized_name": "example ltd"
      }
    },
    "ORGINT": {
      "data": [
        {
          "organization_id": "o",
          "unit_id": "a",
          "parent_unit_id": "b"
        },
        {
          "organization_id": "o",
          "unit_id": "b",
          "parent_unit_id": "a"
        },
        {
          "organization_id": "o",
          "unit_id": "c",
          "parent_unit_id": "b"
        }
      ],
      "expect": {
        "metrics.hierarchy_cycles": 1,
        "artifacts.cycles.0.unit_ids": [
          "a",
          "b"
        ]
      }
    },
    "TRADEINT": {
      "data": [
        {
          "flow_id": "f1",
          "direction": "EXPORT",
          "commodity": "widgets",
          "origin": "IN",
          "destination": "GB",
          "currency": "INR",
          "value": "0.10",
          "quantity": "2",
          "unit": "kg"
        },
        {
          "flow_id": "f2",
          "direction": "EXPORT",
          "commodity": "widgets",
          "origin": "IN",
          "destination": "GB",
          "currency": "INR",
          "value": "0.20",
          "quantity": "3",
          "unit": "kg"
        },
        {
          "flow_id": "f3",
          "direction": "EXPORT",
          "commodity": "widgets",
          "origin": "IN",
          "destination": "GB",
          "currency": "USD",
          "value": "1",
          "quantity": "1",
          "unit": "kg"
        }
      ],
      "expect": {
        "artifacts.aggregates.0.value": "0.30",
        "artifacts.aggregates.0.quantity": "5",
        "metrics.unique_flows": 3
      }
    },
    "JOBINT": {
      "data": [
        {
          "posting_id": "j",
          "employer_id": "org",
          "role": "Engineer",
          "skills": [
            "Python",
            "PYTHON",
            "SQL"
          ],
          "currency": "INR",
          "pay_period": "year",
          "pay_min": "100",
          "pay_max": "200"
        },
        {
          "posting_id": "j",
          "employer_id": "org",
          "role": "Engineer",
          "skills": [
            "Python",
            "PYTHON",
            "SQL"
          ],
          "currency": "INR",
          "pay_period": "year",
          "pay_min": "100",
          "pay_max": "200"
        }
      ],
      "expect": {
        "metrics.unique_postings": 1,
        "artifacts.declared_skill_counts.python": 1,
        "artifacts.declared_skill_counts.sql": 1
      }
    },
    "OWNERSHIPINT": {
      "data": [
        {
          "owner_id": "a",
          "entity_id": "b",
          "percent": "60"
        },
        {
          "owner_id": "b",
          "entity_id": "c",
          "percent": "50"
        },
        {
          "owner_id": "c",
          "entity_id": "a",
          "percent": "10"
        }
      ],
      "expect": {
        "metrics.cycles": 1,
        "artifacts.indirect_paths.0.path_fraction": "0.3",
        "artifacts.indirect_paths.0.control_inferred": false
      }
    },
    "PROCUREMENTINT": {
      "data": [
        {
          "tender_id": "t",
          "bid_id": "a",
          "vendor_id": "v1",
          "currency": "INR",
          "amount": "100",
          "deadline": "2026-10-14T12:00:00Z",
          "submitted_at": "2026-10-14T11:00:00Z",
          "awarded": false
        },
        {
          "tender_id": "t",
          "bid_id": "b",
          "vendor_id": "v2",
          "currency": "INR",
          "amount": "125",
          "deadline": "2026-10-14T12:00:00Z",
          "submitted_at": "2026-10-14T13:00:00Z",
          "awarded": true
        }
      ],
      "expect": {
        "artifacts.tender_comparisons.0.minimum_supplied_bid": "100",
        "artifacts.bids.1.late_under_declared_deadline": true
      },
      "kind": "award_above_supplied_minimum"
    },
    "CONTRACTINT": {
      "data": [
        {
          "contract_id": "c",
          "currency": "INR",
          "amount": "100",
          "starts_at": "2026-01-01",
          "ends_at": "2026-12-31",
          "payments": [
            {
              "due_at": "2026-02-01",
              "amount": "20"
            },
            {
              "due_at": "2027-01-01",
              "amount": "70"
            }
          ]
        }
      ],
      "expect": {
        "artifacts.contracts.0.payment_schedule_total": "90",
        "artifacts.contracts.0.schedule_difference": "-10",
        "artifacts.contracts.0.payments.1.outside_term": true
      }
    },
    "ADDRESSINT": {
      "data": [
        {
          "address_id": "a",
          "components": {
            "line1": " １２ Road ",
            "city": " DELHI",
            "country": "IN"
          }
        },
        {
          "address_id": "b",
          "components": {
            "line1": "12 road",
            "city": "delhi",
            "country": "in"
          }
        }
      ],
      "expect": {
        "metrics.duplicate_groups": 1,
        "artifacts.addresses.0.geocoded": false
      },
      "kind": "normalized_address_match"
    },
    "PROPERTYINT": {
      "data": [
        {
          "jurisdiction": "IN",
          "parcel_id": "p",
          "title_id": "t",
          "owner_id": "a",
          "valuation": "100",
          "currency": "INR"
        },
        {
          "jurisdiction": "IN",
          "parcel_id": "p",
          "title_id": "t",
          "owner_id": "b",
          "valuation": "100",
          "currency": "INR"
        }
      ],
      "expect": {
        "metrics.title_owner_conflicts": 1
      },
      "kind": "property_title_owner_conflict"
    },
    "ASSETINT": {
      "data": [
        {
          "asset_id": "a",
          "serial_id": "s",
          "currency": "INR",
          "cost": "100",
          "salvage": "20",
          "useful_life_years": "4",
          "elapsed_years": "2"
        },
        {
          "asset_id": "b",
          "serial_id": "s",
          "currency": "INR",
          "cost": "100",
          "salvage": "20",
          "useful_life_years": "4",
          "elapsed_years": "8"
        }
      ],
      "expect": {
        "artifacts.assets.0.carrying_value_under_declared_model": "60",
        "artifacts.assets.1.carrying_value_under_declared_model": "20",
        "metrics.serial_collisions": 1
      }
    },
    "TAXINT": {
      "data": [
        {
          "statement_id": "s",
          "currency": "INR",
          "lines": [
            {
              "line_id": "1",
              "base": "10.05",
              "rate_fraction": "0.10",
              "declared_tax": "1.01"
            },
            {
              "line_id": "2",
              "base": "10.15",
              "rate_fraction": "0.10",
              "declared_tax": "1.02"
            }
          ]
        }
      ],
      "expect": {
        "artifacts.tax_statements.0.lines.0.computed": "1.00",
        "artifacts.tax_statements.0.lines.0.difference": "0.01",
        "artifacts.tax_statements.0.computed_total": "2.02",
        "artifacts.tax_statements.0.law_or_rate_applicability_verified": false
      }
    },
    "INSOLVENCYINT": {
      "data": [
        {
          "proceeding_id": "p",
          "entity_id": "e",
          "jurisdiction": "IN",
          "event_at": "2026-01-01",
          "status": "filed"
        },
        {
          "proceeding_id": "p",
          "entity_id": "e",
          "jurisdiction": "IN",
          "event_at": "2026-09-01",
          "status": "closed"
        },
        {
          "proceeding_id": "p",
          "entity_id": "e",
          "jurisdiction": "IN",
          "event_at": "2026-09-01",
          "status": "open"
        }
      ],
      "expect": {
        "metrics.latest_status_conflicts": 1,
        "artifacts.latest_supplied_events.0.latest_observed_statuses": [
          "closed",
          "open"
        ]
      }
    },
    "MNAINT": {
      "data": [
        {
          "deal_id": "d",
          "acquirer_id": "a",
          "target_id": "b",
          "stage": "CLOSED",
          "at": "2026-01-01",
          "stake_percent": "60"
        },
        {
          "deal_id": "d",
          "acquirer_id": "a",
          "target_id": "b",
          "stage": "ANNOUNCED",
          "at": "2026-02-01",
          "stake_percent": "60"
        }
      ],
      "expect": {
        "metrics.stage_reversals": 1
      },
      "kind": "transaction_milestone_reversal"
    },
    "MARKETINT": {
      "data": [
        {
          "seller_id": "a",
          "market_id": "m",
          "period": "q1",
          "currency": "INR",
          "revenue": "50"
        },
        {
          "seller_id": "b",
          "market_id": "m",
          "period": "q1",
          "currency": "INR",
          "revenue": "50"
        },
        {
          "seller_id": "a",
          "market_id": "m",
          "period": "q1",
          "currency": "USD",
          "revenue": "2"
        }
      ],
      "expect": {
        "artifacts.shares.0.fraction_by_seller.a": "0.5",
        "artifacts.shares.0.hhi_0_10000": "5000.00",
        "artifacts.shares.0.population_coverage_verified": false
      }
    },
    "COMPETITORINT": {
      "data": [
        {
          "product_id": "a",
          "cohort_id": "c",
          "features": [
            "one",
            "two"
          ]
        },
        {
          "product_id": "b",
          "cohort_id": "c",
          "features": [
            "two",
            "three"
          ]
        },
        {
          "product_id": "x",
          "cohort_id": "different",
          "features": [
            "one"
          ]
        }
      ],
      "expect": {
        "artifacts.comparisons.0.common_features": [
          "two"
        ],
        "artifacts.comparisons.0.left_only": [
          "one"
        ],
        "artifacts.comparisons.0.jaccard": 0.3333333333333333
      }
    },
    "CUSTOMERINT": {
      "data": [
        {
          "customer_id": "a",
          "period": "p1",
          "currency": "INR",
          "revenue": "10"
        },
        {
          "customer_id": "b",
          "period": "p1",
          "currency": "INR",
          "revenue": "10"
        },
        {
          "customer_id": "a",
          "period": "p2",
          "currency": "INR",
          "revenue": "30"
        },
        {
          "customer_id": "c",
          "period": "p2",
          "currency": "INR",
          "revenue": "5"
        }
      ],
      "parameters": {
        "ordered_periods": [
          "p1",
          "p2"
        ]
      },
      "expect": {
        "artifacts.cohorts.0.customer_retention_fraction": "0.5",
        "artifacts.cohorts.0.net_revenue_retention": "1.5",
        "artifacts.cohorts.0.lost_customers": 1,
        "artifacts.cohorts.0.new_customers": 1
      }
    }
  },
  "adversarial": {
    "FININT": {
      "entity_id": "org",
      "period": "2026",
      "currency": "INR",
      "assets": true,
      "liabilities": "40.03",
      "equity": "60.07",
      "revenue": "200",
      "operating_profit": "50",
      "current_assets": "30",
      "current_liabilities": "10"
    },
    "CORPINT": {
      "jurisdiction": "in",
      "registry_id": "R",
      "name": " Example   Ltd ",
      "status": "active",
      "valid_from": "2026-01-01",
      "valid_to": "2025-01-01"
    },
    "ORGINT": {
      "organization_id": "o",
      "unit_id": [],
      "parent_unit_id": "b"
    },
    "TRADEINT": {
      "flow_id": "f1",
      "direction": "EXPORT_OR_IMPORT",
      "commodity": "widgets",
      "origin": "IN",
      "destination": "GB",
      "currency": "INR",
      "value": "0.10",
      "quantity": "2",
      "unit": "kg"
    },
    "JOBINT": {
      "posting_id": "j",
      "employer_id": "org",
      "role": "Engineer",
      "skills": [
        "Python",
        "PYTHON",
        "SQL"
      ],
      "currency": "INR",
      "pay_period": "year",
      "pay_min": "300",
      "pay_max": "200"
    },
    "OWNERSHIPINT": {
      "owner_id": "a",
      "entity_id": "b",
      "percent": "101"
    },
    "PROCUREMENTINT": {
      "tender_id": "t",
      "bid_id": "a",
      "vendor_id": "v1",
      "currency": "INR",
      "amount": "100",
      "deadline": "2026-10-14T12:00:00Z",
      "submitted_at": "2026-10-14T11:00:00",
      "awarded": false
    },
    "CONTRACTINT": {
      "contract_id": "c",
      "currency": "INR",
      "amount": "100",
      "starts_at": "2026-01-01",
      "ends_at": "2025-01-01",
      "payments": [
        {
          "due_at": "2026-02-01",
          "amount": "20"
        },
        {
          "due_at": "2027-01-01",
          "amount": "70"
        }
      ]
    },
    "ADDRESSINT": {
      "address_id": "a",
      "components": {
        "line1": "x",
        "lat": "23"
      }
    },
    "PROPERTYINT": {
      "jurisdiction": "IN",
      "parcel_id": "p",
      "title_id": "t",
      "owner_id": "a",
      "valuation": "-1",
      "currency": "INR"
    },
    "ASSETINT": {
      "asset_id": "a",
      "serial_id": "s",
      "currency": "INR",
      "cost": "100",
      "salvage": "20",
      "useful_life_years": "0",
      "elapsed_years": "2"
    },
    "TAXINT": {
      "statement_id": "s",
      "currency": "INR",
      "lines": [
        {
          "line_id": "1",
          "base": "100",
          "rate_fraction": "2",
          "declared_tax": "200"
        }
      ]
    },
    "INSOLVENCYINT": {
      "proceeding_id": "p",
      "entity_id": "e",
      "jurisdiction": "IN",
      "event_at": "2027-01-01",
      "status": "filed"
    },
    "MNAINT": {
      "deal_id": "d",
      "acquirer_id": "a",
      "target_id": "b",
      "stage": "Rumor",
      "at": "2026-01-01",
      "stake_percent": "60"
    },
    "MARKETINT": {
      "seller_id": "a",
      "market_id": "m",
      "period": "q1",
      "currency": "inr",
      "revenue": "50"
    },
    "COMPETITORINT": {
      "product_id": "a",
      "cohort_id": "c",
      "features": "one,two"
    },
    "CUSTOMERINT": {
      "customer_id": "a",
      "period": "p1",
      "currency": "INR",
      "revenue": "nan"
    }
  }
}''')


def resolve(value, path):
    for key in path.split("."):
        value = value[int(key)] if isinstance(value, list) else value[key]
    return value


class EconomicEmployeeTests(unittest.TestCase):
    def analyze(self, label, data, parameters=None):
        payload = {"case_id": "case-economic", "task_id": "task-economic", "discipline": label,
            "objective": "Analyze supplied synthetic corporate records", "as_of": "2026-10-15T00:00:00Z",
            "sources": [{"source_id": "s", "uri": "urn:fixture:economic"}],
            "records": [{"record_id": "r" + str(i), "source_id": "s", "data": row} for i, row in enumerate(data)],
            "parameters": parameters or {}}
        before = copy.deepcopy(payload)
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = invoke_employee(payload, evidence_ids=("evidence-economic",))
        self.assertEqual(payload, before)
        for finding in result["findings"]:
            self.assertTrue(set(finding["record_ids"]) <= {row["record_id"] for row in payload["records"]})
            self.assertEqual(finding["canonical_evidence_ids"], ["evidence-economic"])
        return result

    def test_large_decimal_balance_preserves_fractional_cents(self):
        result = self.analyze("FININT", [{
            "entity_id": "e", "period": "p", "currency": "INR",
            "assets": "100000000000000000000000000000.10", "liabilities": "100000000000000000000000000000",
            "equity": "0.10", "revenue": "0", "operating_profit": "0"}])
        self.assertTrue(result["artifacts"]["statements"][0]["balance_identity_holds"])
        self.assertIsNone(result["artifacts"]["statements"][0]["operating_margin"])

    def test_zero_market_total_is_unknown_share(self):
        result = self.analyze("MARKETINT", [{"seller_id": "a", "market_id": "m", "period": "q1",
                                            "currency": "INR", "revenue": "0"}])
        self.assertIsNone(result["artifacts"]["shares"][0]["hhi_0_10000"])
        self.assertIsNone(result["artifacts"]["shares"][0]["fraction_by_seller"]["a"])

    def test_customer_absent_order_returns_explicit_issue(self):
        result = self.analyze("CUSTOMERINT", CASES["positive"]["CUSTOMERINT"]["data"])
        self.assertEqual(result["artifacts"]["cohorts"], [])
        self.assertIn("customer_period_order_required", {issue["code"] for issue in result["issues"]})


def positive_test(label):
    def test(self):
        case = CASES["positive"][label]
        result = self.analyze(label, case["data"], case.get("parameters"))
        self.assertTrue(result["findings"])
        for path, expected in case["expect"].items():
            self.assertEqual(resolve(result, path), expected, path)
        if case.get("kind"):
            self.assertIn(case["kind"], {finding["kind"] for finding in result["findings"]})
    return test


def adversarial_test(label):
    def test(self):
        result = self.analyze(label, [CASES["adversarial"][label]])
        self.assertEqual(result["status"], "INVALID_DATA")
        self.assertEqual(result["metrics"]["accepted_records"], 0)
        self.assertTrue(result["issues"])
    return test


for _label in CASES["positive"]:
    setattr(EconomicEmployeeTests, "test_" + _label.lower() + "_semantics", positive_test(_label))
    setattr(EconomicEmployeeTests, "test_" + _label.lower() + "_malformed", adversarial_test(_label))


if __name__ == "__main__":
    unittest.main()
