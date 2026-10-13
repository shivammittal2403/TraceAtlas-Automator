from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation, getcontext
from enum import Enum
from typing import Any, Optional

getcontext().prec = 28


class PolicyBlocked(RuntimeError):
    """Raised when a request appears to seek offensive energy/infrastructure action."""


class AssetType(str, Enum):
    POWER_PLANT = "POWER_PLANT"
    GENERATOR = "GENERATOR"
    SOLAR_FARM = "SOLAR_FARM"
    WIND_FARM = "WIND_FARM"
    HYDRO_PLANT = "HYDRO_PLANT"
    NUCLEAR_PLANT = "NUCLEAR_PLANT"
    THERMAL_PLANT = "THERMAL_PLANT"
    GAS_PLANT = "GAS_PLANT"
    COAL_PLANT = "COAL_PLANT"
    BIOMASS_PLANT = "BIOMASS_PLANT"
    GEOTHERMAL_PLANT = "GEOTHERMAL_PLANT"
    BATTERY_STORAGE = "BATTERY_STORAGE"
    PUMPED_STORAGE = "PUMPED_STORAGE"
    TRANSMISSION_ASSET = "TRANSMISSION_ASSET"
    DISTRIBUTION_ASSET = "DISTRIBUTION_ASSET"
    SUBSTATION = "SUBSTATION"
    INTERCONNECTOR = "INTERCONNECTOR"
    PIPELINE = "PIPELINE"
    REFINERY = "REFINERY"
    LNG_TERMINAL = "LNG_TERMINAL"
    FUEL_TERMINAL = "FUEL_TERMINAL"
    STORAGE_TERMINAL = "STORAGE_TERMINAL"
    MICROGRID = "MICROGRID"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class Technology(str, Enum):
    SOLAR_PV = "SOLAR_PV"
    SOLAR_THERMAL = "SOLAR_THERMAL"
    ONSHORE_WIND = "ONSHORE_WIND"
    OFFSHORE_WIND = "OFFSHORE_WIND"
    HYDRO = "HYDRO"
    PUMPED_HYDRO = "PUMPED_HYDRO"
    NUCLEAR = "NUCLEAR"
    COAL = "COAL"
    GAS_CCGT = "GAS_CCGT"
    GAS_OCGT = "GAS_OCGT"
    OIL = "OIL"
    BIOMASS = "BIOMASS"
    WASTE_TO_ENERGY = "WASTE_TO_ENERGY"
    GEOTHERMAL = "GEOTHERMAL"
    BATTERY_LI_ION = "BATTERY_LI_ION"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class FuelType(str, Enum):
    SOLAR = "SOLAR"
    WIND = "WIND"
    WATER = "WATER"
    NUCLEAR = "NUCLEAR"
    COAL = "COAL"
    NATURAL_GAS = "NATURAL_GAS"
    OIL = "OIL"
    BIOMASS = "BIOMASS"
    WASTE = "WASTE"
    GEOTHERMAL = "GEOTHERMAL"
    HYDROGEN = "HYDROGEN"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class LocationPrecision(str, Enum):
    COUNTRY = "COUNTRY"
    REGION = "REGION"
    CITY = "CITY"
    INDUSTRIAL_AREA = "INDUSTRIAL_AREA"
    PUBLIC_SITE = "PUBLIC_SITE"
    EXACT_PUBLIC_LOCATION = "EXACT_PUBLIC_LOCATION"
    RESTRICTED_DETAIL = "RESTRICTED_DETAIL"
    UNKNOWN = "UNKNOWN"


class AssetStatus(str, Enum):
    PLANNED = "PLANNED"
    ANNOUNCED = "ANNOUNCED"
    PERMITTED = "PERMITTED"
    FINANCED_REPORTED = "FINANCED_REPORTED"
    UNDER_CONSTRUCTION = "UNDER_CONSTRUCTION"
    COMMISSIONING = "COMMISSIONING"
    OPERATING = "OPERATING"
    PARTIALLY_OPERATING = "PARTIALLY_OPERATING"
    MOTHBALLED = "MOTHBALLED"
    MAINTENANCE = "MAINTENANCE"
    RETIRED = "RETIRED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class ProjectStage(str, Enum):
    PLANNED = "PLANNED"
    ANNOUNCED = "ANNOUNCED"
    PERMITTED = "PERMITTED"
    FINANCED_REPORTED = "FINANCED_REPORTED"
    UNDER_CONSTRUCTION = "UNDER_CONSTRUCTION"
    COMMISSIONING = "COMMISSIONING"
    OPERATING = "OPERATING"
    PARTIALLY_OPERATING = "PARTIALLY_OPERATING"
    RETIRED = "RETIRED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


class HierarchyLevel(str, Enum):
    SITE = "SITE"
    PLANT = "PLANT"
    UNIT = "UNIT"
    PHASE = "PHASE"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


class CapacityBasis(str, Enum):
    NAMEPLATE = "NAMEPLATE"
    INSTALLED = "INSTALLED"
    AVAILABLE = "AVAILABLE"
    DEPENDABLE = "DEPENDABLE"
    CONTRACTED = "CONTRACTED"
    DISPATCHED_OUTPUT = "DISPATCHED_OUTPUT"
    ACTUAL_GENERATION = "ACTUAL_GENERATION"
    STORAGE_POWER = "STORAGE_POWER"
    STORAGE_ENERGY = "STORAGE_ENERGY"
    UNKNOWN = "UNKNOWN"


class Metric(str, Enum):
    POWER = "POWER"
    ENERGY = "ENERGY"


class OutageType(str, Enum):
    PLANNED_MAINTENANCE = "PLANNED_MAINTENANCE"
    UNPLANNED_OUTAGE = "UNPLANNED_OUTAGE"
    CURTAILMENT = "CURTAILMENT"
    DERATING = "DERATING"
    FORCED_OUTAGE = "FORCED_OUTAGE"
    UNKNOWN = "UNKNOWN"


class OutageCauseState(str, Enum):
    OFFICIALLY_REPORTED = "OFFICIALLY_REPORTED"
    TECHNICALLY_SUPPORTED = "TECHNICALLY_SUPPORTED"
    PROBABLE = "PROBABLE"
    POSSIBLE = "POSSIBLE"
    DISPUTED = "DISPUTED"
    UNKNOWN = "UNKNOWN"


class IncidentType(str, Enum):
    EQUIPMENT_FAILURE = "EQUIPMENT_FAILURE"
    FIRE = "FIRE"
    WEATHER_DAMAGE = "WEATHER_DAMAGE"
    CYBER_INCIDENT = "CYBER_INCIDENT"
    SAFETY_EVENT = "SAFETY_EVENT"
    FUEL_INTERRUPTION = "FUEL_INTERRUPTION"
    REGULATORY_SHUTDOWN = "REGULATORY_SHUTDOWN"
    PHYSICAL_INCIDENT = "PHYSICAL_INCIDENT"
    UNKNOWN = "UNKNOWN"


class DependencyType(str, Enum):
    FUEL = "FUEL"
    EQUIPMENT = "EQUIPMENT"
    VENDOR = "VENDOR"
    EPC = "EPC"
    O_AND_M = "O_AND_M"
    TRANSPORT = "TRANSPORT"
    SOFTWARE = "SOFTWARE"
    TELECOM = "TELECOM"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN"


@dataclass
class Evidence:
    evidence_id: str
    source_id: str
    source_type: str
    content: Any
    reliability: str = "UNKNOWN"
    observed_at: Optional[str] = None
    effective_at: Optional[str] = None
    dependencies: list[str] = field(default_factory=list)

    def digest(self) -> str:
        payload = json.dumps(
            {
                "source_id": self.source_id,
                "source_type": self.source_type,
                "content": self.content,
                "reliability": self.reliability,
                "observed_at": self.observed_at,
                "effective_at": self.effective_at,
                "dependencies": self.dependencies,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]


@dataclass
class CapacityClaim:
    claim_id: str
    asset_id: str
    metric: Metric
    value_normalized: Decimal
    unit_original: str
    unit_normalized: str
    basis: CapacityBasis
    basis_detail: str
    evidence_id: str
    observed_at: Optional[str] = None
    effective_at: Optional[str] = None


@dataclass
class Asset:
    asset_id: str
    name: str = ""
    asset_type: AssetType = AssetType.UNKNOWN
    technology: Technology = Technology.UNKNOWN
    fuel_type: FuelType = FuelType.UNKNOWN
    owner: str = ""
    operator: str = ""
    country: str = ""
    region: str = ""
    location_precision: LocationPrecision = LocationPrecision.UNKNOWN
    critical_infrastructure: bool = False
    status: AssetStatus = AssetStatus.UNKNOWN
    project_stage: ProjectStage = ProjectStage.UNKNOWN
    commissioned_at: Optional[str] = None
    retired_at: Optional[str] = None
    parent_asset_id: Optional[str] = None
    hierarchy_level: HierarchyLevel = HierarchyLevel.UNKNOWN
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Outage:
    outage_id: str
    asset_id: str
    start: Optional[str] = None
    end: Optional[str] = None
    outage_type: OutageType = OutageType.UNKNOWN
    cause_state: OutageCauseState = OutageCauseState.UNKNOWN
    reported_cause: str = ""
    capacity_impact_mw: Optional[Decimal] = None
    customers_affected: Optional[int] = None
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Incident:
    incident_id: str
    asset_id: str
    time: Optional[str] = None
    incident_type: IncidentType = IncidentType.UNKNOWN
    official_description: str = ""
    cyber_ot_context: str = ""
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class Dependency:
    dependency_id: str
    asset_id: str
    dependency_type: DependencyType
    counterparty: str
    detail: str = ""
    evidence_ids: list[str] = field(default_factory=list)


@dataclass
class DemandObservation:
    observation_id: str
    region: str
    peak_demand_mw: Decimal
    observed_at: Optional[str] = None
    evidence_id: Optional[str] = None


@dataclass
class PriceObservation:
    observation_id: str
    market: str
    price: Decimal
    currency: str
    observed_at: Optional[str] = None
    evidence_id: Optional[str] = None


class EnergyInt:
    """
    Compact defensive ENERGYINT skeleton.

    Purpose:
    - Resolve energy assets, owners, operators, capacity basis, project lifecycle,
      outages, dependencies, source independence, contradictions, and resilience context.

    Hard boundary:
    - Does NOT plan, enable, optimize, or support attacks, sabotage, disruption,
      SCADA manipulation, safety bypass, or critical-infrastructure targeting.
    """

    PROHIBITED_PATTERNS = (
        "plan attack",
        "attack plan",
        "target ranking",
        "rank assets by attack",
        "easiest asset",
        "weakest substation",
        "sabotage",
        "disrupt grid",
        "cause outage",
        "maximize outage",
        "blackout optimization",
        "grid collapse",
        "bypass safety",
        "safety bypass",
        "disable relay",
        "relay setting",
        "protection setting",
        "scada command",
        "plc attack",
        "ics malware",
        "control manipulation",
        "setpoint manipulation",
        "intrusion path",
        "patrol avoidance",
        "camera evasion",
        "rupture pipeline",
        "destroy transformer",
        "exploit cve",
        "scan ot",
        "credential attack",
        "unauthorized access",
        "take over scada",
    )

    OFFICIAL_SOURCE_TYPES = {
        "regulator",
        "energy_ministry",
        "grid_operator",
        "system_operator",
        "market_operator",
        "utility_filing",
        "official_statistics",
        "government_dataset",
        "permit",
        "environmental_filing",
        "annual_report",
    }

    POWER_TO_MW = {
        "W": Decimal("0.000001"),
        "KW": Decimal("0.001"),
        "MW": Decimal("1"),
        "GW": Decimal("1000"),
        "MWAC": Decimal("1"),
        "MWDC": Decimal("1"),
    }

    ENERGY_TO_MWH = {
        "WH": Decimal("0.000001"),
        "KWH": Decimal("0.001"),
        "MWH": Decimal("1"),
        "GWH": Decimal("1000"),
        "TWH": Decimal("1000000"),
    }

    INSTALLED_ELIGIBLE_STATUS = {
        AssetStatus.OPERATING,
        AssetStatus.PARTIALLY_OPERATING,
        AssetStatus.MAINTENANCE,
        AssetStatus.MOTHBALLED,
    }

    AVAILABLE_ELIGIBLE_STATUS = {
        AssetStatus.OPERATING,
        AssetStatus.PARTIALLY_OPERATING,
        AssetStatus.MAINTENANCE,
    }

    PRE_OPERATIONAL_STAGES = {
        ProjectStage.PLANNED,
        ProjectStage.ANNOUNCED,
        ProjectStage.PERMITTED,
        ProjectStage.FINANCED_REPORTED,
        ProjectStage.UNDER_CONSTRUCTION,
        ProjectStage.CANCELLED,
    }

    def __init__(
        self,
        case_id: str,
        objective: str,
        scope: str,
        questions: Optional[list[str]] = None,
    ):
        self._guard(objective)
        self._guard(scope)
        for q in questions or []:
            self._guard(q)

        self.case_id = case_id
        self.objective = objective
        self.scope = scope

        self.evidence: dict[str, Evidence] = {}
        self.assets: dict[str, Asset] = {}
        self.capacity_claims: list[CapacityClaim] = []
        self.outages: list[Outage] = []
        self.incidents: list[Incident] = []
        self.dependencies: list[Dependency] = []
        self.demand_observations: list[DemandObservation] = []
        self.price_observations: list[PriceObservation] = []

        self.duplicate_groups: dict[str, list[str]] = {}
        self.duplicate_member_to_rep: dict[str, str] = {}

    @classmethod
    def _guard(cls, text: str) -> None:
        low = (text or "").lower()
        for pattern in cls.PROHIBITED_PATTERNS:
            if pattern in low:
                raise PolicyBlocked(
                    f"Policy blocked: '{pattern}'. ENERGYINT supports defensive, authorized, "
                    "resilience-oriented analysis only."
                )

    @staticmethod
    def _id(prefix: str) -> str:
        return f"{prefix}-{uuid.uuid4().hex[:8]}"

    @staticmethod
    def _decimal(value: Any, field_name: str) -> Decimal:
        try:
            d = Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid decimal for {field_name}: {value!r}") from exc
        if d < 0:
            raise ValueError(f"{field_name} must be non-negative")
        return d

    @staticmethod
    def _enum(enum_cls, value: Any, default: Any):
        if isinstance(value, enum_cls):
            return value
        if value is None:
            return default
        key = str(value).strip().upper().replace("-", "_").replace(" ", "_")
        return getattr(enum_cls, key, default)

    @staticmethod
    def _norm_text(value: Any) -> str:
        return "".join(ch for ch in str(value or "").lower() if ch.isalnum())

    @staticmethod
    def _ts(value: Optional[str]) -> str:
        return value or ""

    def _to_mw(self, value: Any, unit: str) -> Decimal:
        u = str(unit).strip().upper().replace(" ", "")
        if u not in self.POWER_TO_MW:
            raise ValueError(f"Unsupported power unit: {unit}")
        return self._decimal(value, "power value") * self.POWER_TO_MW[u]

    def _to_mwh(self, value: Any, unit: str) -> Decimal:
        u = str(unit).strip().upper().replace(" ", "")
        if u not in self.ENERGY_TO_MWH:
            raise ValueError(f"Unsupported energy unit: {unit}")
        return self._decimal(value, "energy value") * self.ENERGY_TO_MWH[u]

    def add_evidence(
        self,
        source_id: str,
        source_type: str,
        content: Any,
        reliability: str = "UNKNOWN",
        observed_at: Optional[str] = None,
        effective_at: Optional[str] = None,
        dependencies: Optional[list[str]] = None,
    ) -> Evidence:
        ev = Evidence(
            evidence_id=self._id("EV"),
            source_id=source_id,
            source_type=source_type.lower(),
            content=content,
            reliability=reliability.upper(),
            observed_at=observed_at,
            effective_at=effective_at,
            dependencies=dependencies or [],
        )
        self.evidence[ev.evidence_id] = ev
        return ev

    def add_asset(
        self,
        asset_id: Optional[str] = None,
        name: str = "",
        asset_type: Any = AssetType.UNKNOWN,
        technology: Any = Technology.UNKNOWN,
        fuel_type: Any = FuelType.UNKNOWN,
        owner: str = "",
        operator: str = "",
        country: str = "",
        region: str = "",
        location_precision: Any = LocationPrecision.UNKNOWN,
        critical_infrastructure: bool = False,
        status: Any = AssetStatus.UNKNOWN,
        project_stage: Any = ProjectStage.UNKNOWN,
        commissioned_at: Optional[str] = None,
        retired_at: Optional[str] = None,
        parent_asset_id: Optional[str] = None,
        hierarchy_level: Any = HierarchyLevel.UNKNOWN,
        evidence_ids: Optional[list[str]] = None,
    ) -> Asset:
        aid = asset_id or self._id("ASSET")
        asset = Asset(
            asset_id=aid,
            name=name,
            asset_type=self._enum(AssetType, asset_type, AssetType.UNKNOWN),
            technology=self._enum(Technology, technology, Technology.UNKNOWN),
            fuel_type=self._enum(FuelType, fuel_type, FuelType.UNKNOWN),
            owner=owner,
            operator=operator,
            country=country,
            region=region,
            location_precision=self._enum(LocationPrecision, location_precision, LocationPrecision.UNKNOWN),
            critical_infrastructure=bool(critical_infrastructure),
            status=self._enum(AssetStatus, status, AssetStatus.UNKNOWN),
            project_stage=self._enum(ProjectStage, project_stage, ProjectStage.UNKNOWN),
            commissioned_at=commissioned_at,
            retired_at=retired_at,
            parent_asset_id=parent_asset_id,
            hierarchy_level=self._enum(HierarchyLevel, hierarchy_level, HierarchyLevel.UNKNOWN),
            evidence_ids=evidence_ids or [],
        )
        self.assets[aid] = asset
        return asset

    def add_capacity_claim(
        self,
        asset_id: str,
        metric: Any,
        value: Any,
        unit: str,
        basis: Any,
        evidence_id: str,
        basis_detail: Optional[str] = None,
        observed_at: Optional[str] = None,
        effective_at: Optional[str] = None,
    ) -> CapacityClaim:
        if asset_id not in self.assets:
            raise KeyError(f"Unknown asset: {asset_id}")
        if evidence_id not in self.evidence:
            raise KeyError(f"Unknown evidence: {evidence_id}")

        m = self._enum(Metric, metric, None)
        b = self._enum(CapacityBasis, basis, None)
        if m is None:
            raise ValueError("metric must be POWER or ENERGY")
        if b is None:
            raise ValueError("basis must be a valid CapacityBasis")

        if m == Metric.POWER:
            norm = self._to_mw(value, unit)
            unit_norm = "MW"
        else:
            norm = self._to_mwh(value, unit)
            unit_norm = "MWh"

        claim = CapacityClaim(
            claim_id=self._id("CAP"),
            asset_id=asset_id,
            metric=m,
            value_normalized=norm,
            unit_original=str(unit),
            unit_normalized=unit_norm,
            basis=b,
            basis_detail=self._norm_text(basis_detail or unit),
            evidence_id=evidence_id,
            observed_at=observed_at,
            effective_at=effective_at,
        )
        self.capacity_claims.append(claim)
        return claim

    def add_outage(
        self,
        asset_id: str,
        start: Optional[str] = None,
        end: Optional[str] = None,
        outage_type: Any = OutageType.UNKNOWN,
        cause_state: Any = OutageCauseState.UNKNOWN,
        reported_cause: str = "",
        capacity_impact_mw: Any = None,
        customers_affected: Optional[int] = None,
        evidence_ids: Optional[list[str]] = None,
    ) -> Outage:
        if asset_id not in self.assets:
            raise KeyError(f"Unknown asset: {asset_id}")

        impact = None
        if capacity_impact_mw is not None:
            impact = self._decimal(capacity_impact_mw, "capacity_impact_mw")

        outage = Outage(
            outage_id=self._id("OUT"),
            asset_id=asset_id,
            start=start,
            end=end,
            outage_type=self._enum(OutageType, outage_type, OutageType.UNKNOWN),
            cause_state=self._enum(OutageCauseState, cause_state, OutageCauseState.UNKNOWN),
            reported_cause=reported_cause,
            capacity_impact_mw=impact,
            customers_affected=customers_affected,
            evidence_ids=evidence_ids or [],
        )
        self.outages.append(outage)
        return outage

    def add_incident(
        self,
        asset_id: str,
        time: Optional[str] = None,
        incident_type: Any = IncidentType.UNKNOWN,
        official_description: str = "",
        cyber_ot_context: str = "",
        evidence_ids: Optional[list[str]] = None,
    ) -> Incident:
        if asset_id not in self.assets:
            raise KeyError(f"Unknown asset: {asset_id}")

        inc = Incident(
            incident_id=self._id("INC"),
            asset_id=asset_id,
            time=time,
            incident_type=self._enum(IncidentType, incident_type, IncidentType.UNKNOWN),
            official_description=official_description,
            cyber_ot_context=cyber_ot_context,
            evidence_ids=evidence_ids or [],
        )
        self.incidents.append(inc)
        return inc

    def add_dependency(
        self,
        asset_id: str,
        dependency_type: Any,
        counterparty: str,
        detail: str = "",
        evidence_ids: Optional[list[str]] = None,
    ) -> Dependency:
        if asset_id not in self.assets:
            raise KeyError(f"Unknown asset: {asset_id}")

        dep = Dependency(
            dependency_id=self._id("DEP"),
            asset_id=asset_id,
            dependency_type=self._enum(DependencyType, dependency_type, DependencyType.UNKNOWN),
            counterparty=counterparty,
            detail=detail,
            evidence_ids=evidence_ids or [],
        )
        self.dependencies.append(dep)
        return dep

    def add_demand_observation(
        self,
        region: str,
        peak_demand_mw: Any,
        unit: str = "MW",
        observed_at: Optional[str] = None,
        evidence_id: Optional[str] = None,
    ) -> DemandObservation:
        obs = DemandObservation(
            observation_id=self._id("DEM"),
            region=region,
            peak_demand_mw=self._to_mw(peak_demand_mw, unit),
            observed_at=observed_at,
            evidence_id=evidence_id,
        )
        self.demand_observations.append(obs)
        return obs

    def add_price_observation(
        self,
        market: str,
        price: Any,
        currency: str,
        observed_at: Optional[str] = None,
        evidence_id: Optional[str] = None,
    ) -> PriceObservation:
        obs = PriceObservation(
            observation_id=self._id("PRC"),
            market=market,
            price=self._decimal(price, "price"),
            currency=currency.upper(),
            observed_at=observed_at,
            evidence_id=evidence_id,
        )
        self.price_observations.append(obs)
        return obs

    def _dedupe_assets(self) -> None:
        self.duplicate_groups.clear()
        self.duplicate_member_to_rep.clear()

        by_key: dict[tuple[str, ...], list[str]] = defaultdict(list)

        for asset in self.assets.values():
            key_parts = (
                self._norm_text(asset.name),
                self._norm_text(asset.region),
                asset.asset_type.value,
                asset.technology.value,
                self._norm_text(asset.owner),
                self._norm_text(asset.operator),
            )
            if all(key_parts):
                by_key[key_parts].append(asset.asset_id)

        idx = 1
        for ids in by_key.values():
            if len(ids) > 1:
                group_id = f"DUP-{idx}"
                rep = sorted(ids)[0]
                self.duplicate_groups[group_id] = sorted(ids)
                for member in ids:
                    self.duplicate_member_to_rep[member] = rep
                idx += 1

        for asset_id in self.assets:
            self.duplicate_member_to_rep.setdefault(asset_id, asset_id)

    def _rep_id(self, asset_id: Optional[str]) -> Optional[str]:
        if not asset_id:
            return None
        return self.duplicate_member_to_rep.get(asset_id, asset_id)

    def _representatives(self) -> set[str]:
        return set(self.duplicate_member_to_rep.values())

    def _claim_is_eligible(self, claim: CapacityClaim, as_of: Optional[str]) -> bool:
        if not as_of:
            return True
        if claim.effective_at and claim.effective_at > as_of:
            return False
        if claim.observed_at and claim.observed_at > as_of:
            return False
        return True

    def _latest_per_basis_detail(
        self,
        claims: list[CapacityClaim],
        as_of: Optional[str],
    ) -> dict[str, CapacityClaim]:
        groups: dict[str, CapacityClaim] = {}
        for claim in claims:
            if not self._claim_is_eligible(claim, as_of):
                continue
            prev = groups.get(claim.basis_detail)
            if prev is None or self._ts(claim.effective_at or claim.observed_at) > self._ts(
                prev.effective_at or prev.observed_at
            ):
                groups[claim.basis_detail] = claim
        return groups

    def _choose_claim(
        self,
        claims: list[CapacityClaim],
        as_of: Optional[str],
        preference: list[str],
    ) -> Optional[CapacityClaim]:
        grouped = self._latest_per_basis_detail(claims, as_of)
        if not grouped:
            return None

        best: Optional[CapacityClaim] = None
        best_key: Optional[tuple[int, str]] = None

        for detail, claim in grouped.items():
            try:
                pref_idx = preference.index(detail)
            except ValueError:
                pref_idx = len(preference)
            key = (pref_idx, self._ts(claim.effective_at or claim.observed_at))
            if best is None or best_key is None:
                best, best_key = claim, key
            elif key[0] < best_key[0] or (key[0] == best_key[0] and key[1] > best_key[1]):
                best, best_key = claim, key

        return best

    def _resolve_asset_capacity(self, asset_id: str, as_of: Optional[str]) -> dict[str, Any]:
        claims = [c for c in self.capacity_claims if c.asset_id == asset_id]

        installed_claims = [
            c for c in claims if c.metric == Metric.POWER and c.basis in (CapacityBasis.INSTALLED, CapacityBasis.NAMEPLATE)
        ]
        available_claims = [c for c in claims if c.metric == Metric.POWER and c.basis == CapacityBasis.AVAILABLE]
        dependable_claims = [c for c in claims if c.metric == Metric.POWER and c.basis == CapacityBasis.DEPENDABLE]
        storage_power_claims = [c for c in claims if c.metric == Metric.POWER and c.basis == CapacityBasis.STORAGE_POWER]
        storage_energy_claims = [c for c in claims if c.metric == Metric.ENERGY and c.basis == CapacityBasis.STORAGE_ENERGY]
        generation_claims = [c for c in claims if c.metric == Metric.ENERGY and c.basis == CapacityBasis.ACTUAL_GENERATION]

        installed = self._choose_claim(
            installed_claims,
            as_of,
            ["mwac", "mw", "net", "mwdc", "gross", ""],
        )
        available = self._choose_claim(available_claims, as_of, ["mw", "net", "gross", ""])
        dependable = self._choose_claim(dependable_claims, as_of, ["mw", "net", "gross", ""])
        storage_power = self._choose_claim(storage_power_claims, as_of, ["mw", ""])
        storage_energy = self._choose_claim(storage_energy_claims, as_of, ["mwh", "gwh", "kwh", "twh", ""])
        actual_generation = self._choose_claim(generation_claims, as_of, ["mwh", "gwh", "kwh", "twh", ""])

        ambiguities = []
        for label, claim_list in [
            ("installed", installed_claims),
            ("available", available_claims),
            ("dependable", dependable_claims),
        ]:
            details = {
                c.basis_detail
                for c in claim_list
                if self._claim_is_eligible(c, as_of)
            }
            if len(details) > 1:
                ambiguities.append(f"{label}_basis_ambiguous:{','.join(sorted(details))}")

        return {
            "installed": installed,
            "available": available,
            "dependable": dependable,
            "storage_power": storage_power,
            "storage_energy": storage_energy,
            "actual_generation": actual_generation,
            "ambiguities": ambiguities,
        }

    def _include_installed(self, asset: Asset, resolved: dict[str, Any]) -> bool:
        return (
            asset.status in self.INSTALLED_ELIGIBLE_STATUS
            and asset.project_stage not in self.PRE_OPERATIONAL_STAGES
            and asset.retired_at is None
            and resolved.get("installed") is not None
        )

    def _include_available(self, asset: Asset, resolved: dict[str, Any]) -> bool:
        return (
            asset.status in self.AVAILABLE_ELIGIBLE_STATUS
            and asset.project_stage not in self.PRE_OPERATIONAL_STAGES
            and asset.retired_at is None
            and resolved.get("available") is not None
        )

    def _descendants(self, root: str, children: dict[str, list[str]], visited: set[str]) -> list[str]:
        result = []
        for child in children.get(root, []):
            if child not in visited:
                visited.add(child)
                result.append(child)
                result.extend(self._descendants(child, children, visited))
        return result

    def _aggregate_capacity(
        self,
        reps: set[str],
        resolved: dict[str, dict[str, Any]],
        children: dict[str, list[str]],
        roots: list[str],
        include_fn,
        basis_key: str,
    ) -> tuple[Decimal, list[dict[str, Any]], list[str]]:
        total = Decimal("0")
        used = []
        notes = []

        for root in roots:
            asset = self.assets[root]
            if not include_fn(asset, resolved[root]):
                continue

            claim = resolved[root].get(basis_key)
            if claim is not None:
                total += claim.value_normalized
                used.append(
                    {
                        "asset_id": root,
                        "asset_name": asset.name,
                        "value_mw": str(claim.value_normalized),
                        "basis_detail": claim.basis_detail,
                        "evidence_id": claim.evidence_id,
                    }
                )
            else:
                descendants = self._descendants(root, children, {root})
                for desc in descendants:
                    dasset = self.assets[desc]
                    if not include_fn(dasset, resolved[desc]):
                        continue
                    dclaim = resolved[desc].get(basis_key)
                    if dclaim is not None:
                        total += dclaim.value_normalized
                        used.append(
                            {
                                "asset_id": desc,
                                "asset_name": dasset.name,
                                "value_mw": str(dclaim.value_normalized),
                                "basis_detail": dclaim.basis_detail,
                                "evidence_id": dclaim.evidence_id,
                            }
                        )
                if descendants:
                    notes.append(f"root_{root}_had_no_direct_capacity_used_children_for_{basis_key}")

        return total, used, notes

    def _source_independence(self) -> dict[str, Any]:
        dependent_ids: set[str] = set()
        edges = []
        by_source: dict[str, list[str]] = defaultdict(list)

        for ev in self.evidence.values():
            by_source[ev.source_id].append(ev.evidence_id)
            for dep in ev.dependencies:
                if dep in self.evidence:
                    edges.append(
                        {
                            "derived_evidence_id": ev.evidence_id,
                            "derived_source_id": ev.source_id,
                            "upstream_evidence_id": dep,
                            "upstream_source_id": self.evidence[dep].source_id,
                            "relationship": "DEPENDENT",
                        }
                    )
                    dependent_ids.add(ev.evidence_id)

        source_has_independent = defaultdict(bool)
        for ev in self.evidence.values():
            if ev.evidence_id not in dependent_ids:
                source_has_independent[ev.source_id] = True

        independent_sources = sorted(sid for sid, ok in source_has_independent.items() if ok)

        return {
            "independent_source_count": len(independent_sources),
            "independent_sources": independent_sources,
            "all_sources": sorted(by_source),
            "dependency_edges": edges,
            "dependent_evidence_ids": sorted(dependent_ids),
        }

    def _facts(self) -> list[dict[str, Any]]:
        facts = []
        for claim in self.capacity_claims:
            ev = self.evidence.get(claim.evidence_id)
            asset = self.assets.get(claim.asset_id)
            if not ev or not asset:
                continue

            official = ev.source_type in self.OFFICIAL_SOURCE_TYPES or ev.reliability in {"PRIMARY", "OFFICIAL", "REGULATOR"}
            state = "SUPPORTED_SOURCE_REPORTED" if official else "CANDIDATE_SOURCE_REPORTED"

            unit = "MW" if claim.metric == Metric.POWER else "MWh"
            when = claim.effective_at or claim.observed_at or "unknown time"

            facts.append(
                {
                    "fact_id": self._id("FACT"),
                    "state": state,
                    "asset_id": asset.asset_id,
                    "asset_name": asset.name,
                    "statement": (
                        f"{ev.source_id} reports {asset.name} has {claim.basis.value} "
                        f"{claim.value_normalized} {unit} ({claim.basis_detail or 'basis unspecified'}) "
                        f"as of {when}."
                    ),
                    "evidence_id": ev.evidence_id,
                    "evidence_digest": ev.digest(),
                    "claim_id": claim.claim_id,
                }
            )
        return facts

    def _contradictions(self) -> list[dict[str, Any]]:
        contradictions = []
        groups: dict[tuple[str, Metric, CapacityBasis, str], list[CapacityClaim]] = defaultdict(list)

        for claim in self.capacity_claims:
            groups[(claim.asset_id, claim.metric, claim.basis, claim.basis_detail)].append(claim)

        for (asset_id, metric, basis, basis_detail), claims in groups.items():
            if len(claims) < 2:
                continue

            values = [c.value_normalized for c in claims]
            mn, mx = min(values), max(values)
            denom = max(mx, Decimal("1"))
            if (mx - mn) / denom > Decimal("0.01"):
                contradictions.append(
                    {
                        "type": "CAPACITY_VALUE_CONFLICT",
                        "asset_id": asset_id,
                        "metric": metric.value,
                        "basis": basis.value,
                        "basis_detail": basis_detail,
                        "values": [str(v) for v in values],
                        "claim_ids": [c.claim_id for c in claims],
                        "note": "Same asset, metric, basis, and basis detail conflict beyond 1% tolerance.",
                    }
                )

        return contradictions

    def _active_outage_impact(self, as_of: Optional[str]) -> tuple[Decimal, list[dict[str, Any]]]:
        by_asset: dict[str, Decimal] = defaultdict(lambda: Decimal("0"))
        details = []

        for outage in self.outages:
            if as_of:
                if outage.start and outage.start > as_of:
                    continue
                if outage.end and outage.end < as_of:
                    continue

            rep = self._rep_id(outage.asset_id)
            if not rep:
                continue

            impact = outage.capacity_impact_mw or Decimal("0")
            if impact > by_asset[rep]:
                by_asset[rep] = impact

            details.append(
                {
                    "outage_id": outage.outage_id,
                    "asset_id": rep,
                    "start": outage.start,
                    "end": outage.end,
                    "type": outage.outage_type.value,
                    "cause_state": outage.cause_state.value,
                    "reported_cause": outage.reported_cause,
                    "capacity_impact_mw": str(impact),
                    "customers_affected": outage.customers_affected,
                    "evidence_ids": outage.evidence_ids,
                }
            )

        return sum(by_asset.values(), Decimal("0")), details

    def _latest_demand(self) -> Optional[DemandObservation]:
        if not self.demand_observations:
            return None
        return max(self.demand_observations, key=lambda d: self._ts(d.observed_at))

    def _hypotheses(
        self,
        facts: list[dict[str, Any]],
        ambiguities: list[str],
        active_outage_impact: Decimal,
        pre_operational_with_capacity_claims: bool,
    ) -> list[dict[str, Any]]:
        official_count = sum(1 for f in facts if f["state"] == "SUPPORTED_SOURCE_REPORTED")
        base_conf = official_count / max(1, len(facts)) if facts else 0.0

        h1_conf = base_conf
        if ambiguities:
            h1_conf *= Decimal("0.7")

        hypotheses = [
            {
                "hypothesis_id": "H1",
                "description": "Reported operating capacity is supported by latest official installed-capacity evidence.",
                "confidence": float(round(Decimal(str(h1_conf)), 3)),
                "supporting_states": ["SUPPORTED_SOURCE_REPORTED"],
                "opposing_signals": ambiguities,
                "falsification_conditions": [
                    "Newer official filing shows lower operating capacity.",
                    "Capacity claim is found to include planned/non-operating phase.",
                    "Owner/operator or asset identity resolution is wrong.",
                ],
            },
            {
                "hypothesis_id": "H2",
                "description": "Capacity differences reflect AC/DC, gross/net, or other basis differences rather than data error.",
                "confidence": 0.8 if ambiguities else 0.2,
                "supporting_states": ["CAPACITY_BASIS_AMBIGUITY"],
                "opposing_signals": [],
                "falsification_conditions": [
                    "Sources use identical basis but still conflict.",
                    "Independent technical documentation confirms single basis.",
                ],
            },
            {
                "hypothesis_id": "H3",
                "description": "A commercial database may be counting announced/under-construction capacity as operating capacity.",
                "confidence": 0.7 if pre_operational_with_capacity_claims else 0.2,
                "supporting_states": ["PRE_OPERATIONAL_ASSET_WITH_CAPACITY_CLAIM"],
                "opposing_signals": [],
                "falsification_conditions": [
                    "Official commissioning evidence confirms operation.",
                    "Database status is corrected by primary source.",
                ],
            },
            {
                "hypothesis_id": "H4",
                "description": "Active outage or derating reduces available capacity relative to installed capacity.",
                "confidence": 0.8 if active_outage_impact > 0 else 0.1,
                "supporting_states": ["ACTIVE_OUTAGE_IMPACT"],
                "opposing_signals": [],
                "falsification_conditions": [
                    "Outage is ended or restored before analysis time.",
                    "Impact figure is duplicate or non-additive.",
                ],
            },
        ]
        return hypotheses

    def _next_actions(self, gaps: list[str], critical: bool) -> list[str]:
        actions = [
            "retrieve_latest_official_regulator_or_grid_operator_filing",
            "verify_commercial_operation_date_and_project_phase",
            "normalize_capacity_basis_before_aggregation",
            "resolve_owner_and_operator_through_authorized_corporate_sources",
            "check_source_independence_and_remove_derived_duplicates",
            "preserve_evidence_hashes_and_source_pedigree",
        ]

        if critical:
            actions.insert(0, "human_review_required_for_critical_infrastructure_sensitivity")

        if any("capacity_basis_ambiguous" in g for g in gaps):
            actions.append("clarify_AC_DC_and_gross_net_capacity_basis")

        if any("outage_cause_unresolved" in g for g in gaps):
            actions.append("review_official_outage_report_before_cause_attribution")

        if any("insufficient_independent_sources" in g for g in gaps):
            actions.append("obtain_one_additional_independent_primary_source")

        return list(dict.fromkeys(actions))

    def _handoffs(self, critical: bool, has_cyber_incident: bool, has_vendor_dep: bool, has_fuel_dep: bool) -> list[str]:
        handoffs = ["HUMAN_REVIEW before consequential energy-security conclusions"]

        if critical:
            handoffs.append("CRITICAL_INFRASTRUCTURE handling: restrict sensitive operational detail")

        if has_cyber_incident:
            handoffs.append("INCIDENTINT / OTINT / CTI for defensive cyber-incident context")

        if has_vendor_dep:
            handoffs.append("SUPPLYCHAININT / TECHINT for equipment and vendor dependency analysis")

        if has_fuel_dep:
            handoffs.append("TRADEINT for fuel import/export and supply-chain flow analysis")

        handoffs.append("CORPINT / OWNERSHIPINT for legal owner and corporate structure verification")
        handoffs.append("LEGALINT for regulatory interpretation")
        handoffs.append("GEOINT only with minimum-necessary location precision")
        return handoffs

    def analyze(self, as_of: Optional[str] = None, questions: Optional[list[str]] = None) -> dict[str, Any]:
        for q in questions or []:
            self._guard(q)

        self._dedupe_assets()
        reps = self._representatives()

        parent_map: dict[str, Optional[str]] = {}
        children: dict[str, list[str]] = defaultdict(list)

        for aid in reps:
            asset = self.assets[aid]
            parent = self._rep_id(asset.parent_asset_id)
            parent_map[aid] = parent
            if parent and parent != aid and parent in reps:
                children[parent].append(aid)

        roots = [
            aid
            for aid in reps
            if not parent_map[aid] or parent_map[aid] not in reps or parent_map[aid] == aid
        ]

        resolved = {aid: self._resolve_asset_capacity(aid, as_of) for aid in reps}

        installed_total, installed_used, installed_notes = self._aggregate_capacity(
            reps, resolved, children, roots, self._include_installed, "installed"
        )
        available_total, available_used, available_notes = self._aggregate_capacity(
            reps, resolved, children, roots, self._include_available, "available"
        )

        dependable_total = Decimal("0")
        dependable_used = []
        for aid in reps:
            asset = self.assets[aid]
            claim = resolved[aid].get("dependable")
            if claim and self._include_available(asset, resolved[aid]):
                dependable_total += claim.value_normalized
                dependable_used.append(
                    {
                        "asset_id": aid,
                        "value_mw": str(claim.value_normalized),
                        "basis_detail": claim.basis_detail,
                        "evidence_id": claim.evidence_id,
                    }
                )

        storage_power_total = Decimal("0")
        storage_energy_total = Decimal("0")
        storage_assets = []
        for aid in reps:
            sp = resolved[aid].get("storage_power")
            se = resolved[aid].get("storage_energy")
            if sp or se:
                asset = self.assets[aid]
                power = sp.value_normalized if sp else Decimal("0")
                energy = se.value_normalized if se else Decimal("0")
                duration = (energy / power) if power > 0 else None
                storage_power_total += power
                storage_energy_total += energy
                storage_assets.append(
                    {
                        "asset_id": aid,
                        "asset_name": asset.name,
                        "power_mw": str(power),
                        "energy_mwh": str(energy),
                        "duration_hours": str(round(duration, 3)) if duration is not None else None,
                    }
                )

        actual_generation_total = Decimal("0")
        generation_assets = []
        for aid in reps:
            gen = resolved[aid].get("actual_generation")
            if gen:
                actual_generation_total += gen.value_normalized
                generation_assets.append(
                    {
                        "asset_id": aid,
                        "generation_mwh": str(gen.value_normalized),
                        "basis_detail": gen.basis_detail,
                        "evidence_id": gen.evidence_id,
                    }
                )

        active_outage_impact, outage_details = self._active_outage_impact(as_of)

        ambiguities = []
        for aid in reps:
            ambiguities.extend(resolved[aid].get("ambiguities", []))

        pre_operational_with_capacity_claims = any(
            self.assets[aid].project_stage in self.PRE_OPERATIONAL_STAGES
            and any(c.asset_id == aid for c in self.capacity_claims)
            for aid in reps
        )

        facts = self._facts()
        contradictions = self._contradictions()
        independence = self._source_independence()
        hypotheses = self._hypotheses(
            facts,
            ambiguities,
            active_outage_impact,
            pre_operational_with_capacity_claims,
        )

        critical_assets = [aid for aid in self.assets if self.assets[aid].critical_infrastructure]
        critical = bool(critical_assets)
        has_cyber_incident = any(i.incident_type == IncidentType.CYBER_INCIDENT for i in self.incidents)
        has_vendor_dep = any(
            d.dependency_type in (DependencyType.VENDOR, DependencyType.EQUIPMENT)
            for d in self.dependencies
        )
        has_fuel_dep = any(d.dependency_type == DependencyType.FUEL for d in self.dependencies)

        latest_demand = self._latest_demand()
        reserve_margin = None
        if latest_demand and latest_demand.peak_demand_mw > 0 and available_total > 0:
            reserve_margin = (available_total - latest_demand.peak_demand_mw) / latest_demand.peak_demand_mw

        common_dependency_counts = Counter(
            (d.dependency_type.value, d.counterparty) for d in self.dependencies
        )

        knowledge_gaps = []
        if not self.assets:
            knowledge_gaps.append("energy_asset_inventory_empty")
        if ambiguities:
            knowledge_gaps.append("capacity_basis_ambiguous")
        if independence["independent_source_count"] < 2:
            knowledge_gaps.append("insufficient_independent_sources")
        if any(self.assets[aid].status == AssetStatus.UNKNOWN for aid in self.assets):
            knowledge_gaps.append("asset_status_unresolved")
        if any(not self.assets[aid].owner for aid in self.assets):
            knowledge_gaps.append("owner_unresolved")
        if any(not self.assets[aid].operator for aid in self.assets):
            knowledge_gaps.append("operator_unresolved")
        if any(o.cause_state == OutageCauseState.UNKNOWN for o in self.outages):
            knowledge_gaps.append("outage_cause_unresolved")
        if critical:
            knowledge_gaps.append("critical_infrastructure_sensitive_detail_boundary")

        next_actions = self._next_actions(knowledge_gaps, critical)
        handoffs = self._handoffs(critical, has_cyber_incident, has_vendor_dep, has_fuel_dep)

        sensitivity_flags = []
        if critical:
            sensitivity_flags.append("CRITICAL_INFRASTRUCTURE_PRESENT")
            sensitivity_flags.append("REDUCE_LOCATION_PRECISION")
            sensitivity_flags.append("NO_ATTACK_SENSITIVE_DETAIL")
        if has_cyber_incident:
            sensitivity_flags.append("CYBER_OT_CONTEXT_RESTRICTED_TO_DEFENSIVE_HANDOFF")

        def _asset_out(asset: Asset) -> dict[str, Any]:
            d = {
                "asset_id": asset.asset_id,
                "name": asset.name,
                "asset_type": asset.asset_type.value,
                "technology": asset.technology.value,
                "fuel_type": asset.fuel_type.value,
                "owner": asset.owner,
                "operator": asset.operator,
                "country": asset.country,
                "region": asset.region,
                "location_precision": asset.location_precision.value,
                "critical_infrastructure": asset.critical_infrastructure,
                "status": asset.status.value,
                "project_stage": asset.project_stage.value,
                "commissioned_at": asset.commissioned_at,
                "retired_at": asset.retired_at,
                "parent_asset_id": asset.parent_asset_id,
                "hierarchy_level": asset.hierarchy_level.value,
                "evidence_ids": asset.evidence_ids,
            }
            if critical and d["location_precision"] in {
                LocationPrecision.EXACT_PUBLIC_LOCATION.value,
                LocationPrecision.RESTRICTED_DETAIL.value,
                LocationPrecision.PUBLIC_SITE.value,
            }:
                d["location_precision"] = LocationPrecision.REGION.value
                d["location_redacted_for_safety"] = True
            return d

        def _claim_out(claim: Optional[CapacityClaim]) -> Optional[dict[str, Any]]:
            if not claim:
                return None
            return {
                "claim_id": claim.claim_id,
                "metric": claim.metric.value,
                "value_normalized": str(claim.value_normalized),
                "unit_normalized": claim.unit_normalized,
                "unit_original": claim.unit_original,
                "basis": claim.basis.value,
                "basis_detail": claim.basis_detail,
                "evidence_id": claim.evidence_id,
                "observed_at": claim.observed_at,
                "effective_at": claim.effective_at,
            }

        report = {
            "case_id": self.case_id,
            "objective": self.objective,
            "authorized_scope": self.scope,
            "as_of": as_of,
            "critical_infrastructure_handling": {
                "critical_infrastructure_present": critical,
                "human_review_required": critical,
                "attack_planning_prohibited": True,
                "sensitive_operational_detail_restricted": True,
            },
            "assets": [_asset_out(a) for a in self.assets.values()],
            "duplicate_asset_groups": self.duplicate_groups,
            "capacity_claims": [_claim_out(c) for c in self.capacity_claims],
            "resolved_capacity_by_asset": {
                aid: {
                    "installed": _claim_out(resolved[aid].get("installed")),
                    "available": _claim_out(resolved[aid].get("available")),
                    "dependable": _claim_out(resolved[aid].get("dependable")),
                    "storage_power": _claim_out(resolved[aid].get("storage_power")),
                    "storage_energy": _claim_out(resolved[aid].get("storage_energy")),
                    "actual_generation": _claim_out(resolved[aid].get("actual_generation")),
                    "ambiguities": resolved[aid].get("ambiguities", []),
                }
                for aid in reps
            },
            "aggregate": {
                "installed_capacity_mw": str(installed_total),
                "available_capacity_mw": str(available_total),
                "dependable_capacity_mw": str(dependable_total),
                "storage_power_mw": str(storage_power_total),
                "storage_energy_mwh": str(storage_energy_total),
                "actual_generation_mwh_reported": str(actual_generation_total),
                "active_outage_impact_mw": str(active_outage_impact),
                "installed_used_assets": installed_used,
                "available_used_assets": available_used,
                "dependable_used_assets": dependable_used,
                "storage_assets": storage_assets,
                "generation_assets": generation_assets,
                "double_count_controls": installed_notes + available_notes,
            },
            "outages": outage_details,
            "incidents": [
                {
                    "incident_id": i.incident_id,
                    "asset_id": self._rep_id(i.asset_id),
                    "time": i.time,
                    "incident_type": i.incident_type.value,
                    "official_description": i.official_description,
                    "cyber_ot_context": i.cyber_ot_context,
                    "evidence_ids": i.evidence_ids,
                }
                for i in self.incidents
            ],
            "dependencies": [
                {
                    "dependency_id": d.dependency_id,
                    "asset_id": self._rep_id(d.asset_id),
                    "dependency_type": d.dependency_type.value,
                    "counterparty": d.counterparty,
                    "detail": d.detail,
                    "evidence_ids": d.evidence_ids,
                }
                for d in self.dependencies
            ],
            "demand": [
                {
                    "observation_id": o.observation_id,
                    "region": o.region,
                    "peak_demand_mw": str(o.peak_demand_mw),
                    "observed_at": o.observed_at,
                    "evidence_id": o.evidence_id,
                }
                for o in self.demand_observations
            ],
            "prices": [
                {
                    "observation_id": o.observation_id,
                    "market": o.market,
                    "price": str(o.price),
                    "currency": o.currency,
                    "observed_at": o.observed_at,
                    "evidence_id": o.evidence_id,
                }
                for o in self.price_observations
            ],
            "resilience": {
                "reserve_margin_vs_latest_peak_demand": str(round(reserve_margin, 4)) if reserve_margin is not None else None,
                "latest_peak_demand_mw": str(latest_demand.peak_demand_mw) if latest_demand else None,
                "common_dependency_counts": [
                    {"dependency_type": k[0], "counterparty": k[1], "count": v}
                    for k, v in common_dependency_counts.most_common()
                ],
                "notes": [
                    "Resilience metrics are defensive only.",
                    "Single point of failure candidates are never treated as targets.",
                ],
            },
            "facts": facts,
            "contradictions": contradictions,
            "source_independence": independence,
            "hypotheses": hypotheses,
            "sensitivity_flags": sensitivity_flags,
            "knowledge_gaps": knowledge_gaps,
            "recommended_next_actions": next_actions,
            "specialist_handoffs": handoffs,
            "limitations": [
                "Compact defensive ENERGYINT skeleton only.",
                "Does not fetch live sources.",
                "Does not replace OT/ICS defensive tooling, grid studies, or human engineers.",
                "Does not perform true dual-AI review; provides deterministic checks and skeptic prompts only.",
                "Never produces attack planning, targeting, sabotage, SCADA manipulation, or safety-bypass content.",
            ],
            "status": "SUCCEEDED" if self.assets and facts and not knowledge_gaps else "PARTIAL",
        }

        return json.loads(json.dumps(report, default=str))


def demo() -> None:
    agent = EnergyInt(
        case_id="ENERGY-DEMO-001",
        objective="Defensive resilience review of a public solar and storage portfolio",
        scope="Public regulator filings, utility reports, and authorized asset summaries only",
    )

    ev_reg = agent.add_evidence(
        source_id="REG-NORTH-01",
        source_type="regulator",
        content={"dataset": "capacity_registry", "asset": "Alpha Solar Farm", "capacity": "500 MWac"},
        reliability="OFFICIAL",
        observed_at="2026-09-01",
        effective_at="2026-09-01",
    )

    ev_util = agent.add_evidence(
        source_id="UTIL-NORTH-01",
        source_type="utility_filing",
        content={"asset": "Alpha Solar Farm", "dc_rating": "600 MWdc", "ac_rating": "500 MWac"},
        reliability="PRIMARY",
        observed_at="2026-08-15",
        effective_at="2026-08-15",
    )

    ev_db = agent.add_evidence(
        source_id="COMMERCIAL-DB-01",
        source_type="commercial_database",
        content={"asset": "Beta Solar Phase II", "status": "OPERATING", "capacity": "300 MWac"},
        reliability="SUPPORTING",
        observed_at="2026-09-10",
        effective_at="2026-09-10",
        dependencies=[ev_reg.evidence_id],
    )

    alpha = agent.add_asset(
        asset_id="ASSET-ALPHA",
        name="Alpha Solar Farm",
        asset_type="SOLAR_FARM",
        technology="SOLAR_PV",
        fuel_type="SOLAR",
        owner="GreenEnergy Holdings",
        operator="Solar Operations Ltd",
        country="Exampleland",
        region="North",
        location_precision="PUBLIC_SITE",
        critical_infrastructure=False,
        status="OPERATING",
        project_stage="OPERATING",
        commissioned_at="2025-06-01",
        hierarchy_level="PLANT",
        evidence_ids=[ev_reg.evidence_id, ev_util.evidence_id],
    )

    agent.add_capacity_claim(
        asset_id=alpha.asset_id,
        metric="POWER",
        value=600,
        unit="MWdc",
        basis="INSTALLED",
        evidence_id=ev_util.evidence_id,
        basis_detail="MWdc",
        observed_at="2026-08-15",
        effective_at="2026-08-15",
    )

    agent.add_capacity_claim(
        asset_id=alpha.asset_id,
        metric="POWER",
        value=500,
        unit="MWac",
        basis="INSTALLED",
        evidence_id=ev_reg.evidence_id,
        basis_detail="MWac",
        observed_at="2026-09-01",
        effective_at="2026-09-01",
    )

    agent.add_capacity_claim(
        asset_id=alpha.asset_id,
        metric="POWER",
        value=450,
        unit="MWac",
        basis="AVAILABLE",
        evidence_id=ev_reg.evidence_id,
        basis_detail="MWac",
        observed_at="2026-09-01",
        effective_at="2026-09-01",
    )

    beta = agent.add_asset(
        asset_id="ASSET-BETA",
        name="Beta Solar Phase II",
        asset_type="SOLAR_FARM",
        technology="SOLAR_PV",
        fuel_type="SOLAR",
        owner="GreenEnergy Holdings",
        operator="Solar Operations Ltd",
        country="Exampleland",
        region="North",
        location_precision="REGION",
        critical_infrastructure=False,
        status="UNDER_CONSTRUCTION",
        project_stage="UNDER_CONSTRUCTION",
        parent_asset_id=None,
        hierarchy_level="PHASE",
        evidence_ids=[ev_db.evidence_id],
    )

    agent.add_capacity_claim(
        asset_id=beta.asset_id,
        metric="POWER",
        value=300,
        unit="MWac",
        basis="INSTALLED",
        evidence_id=ev_db.evidence_id,
        basis_detail="MWac",
        observed_at="2026-09-10",
        effective_at="2026-09-10",
    )

    storage = agent.add_asset(
        asset_id="ASSET-STORAGE-1",
        name="North Battery Storage",
        asset_type="BATTERY_STORAGE",
        technology="BATTERY_LI_ION",
        fuel_type="OTHER",
        owner="GridServices Inc",
        operator="StorageOps Ltd",
        country="Exampleland",
        region="North",
        location_precision="REGION",
        critical_infrastructure=False,
        status="OPERATING",
        project_stage="OPERATING",
        commissioned_at="2026-01-15",
        hierarchy_level="PLANT",
    )

    agent.add_capacity_claim(
        asset_id=storage.asset_id,
        metric="POWER",
        value=50,
        unit="MW",
        basis="STORAGE_POWER",
        evidence_id=ev_reg.evidence_id,
        basis_detail="MW",
        observed_at="2026-09-01",
        effective_at="2026-09-01",
    )

    agent.add_capacity_claim(
        asset_id=storage.asset_id,
        metric="ENERGY",
        value=200,
        unit="MWh",
        basis="STORAGE_ENERGY",
        evidence_id=ev_reg.evidence_id,
        basis_detail="MWh",
        observed_at="2026-09-01",
        effective_at="2026-09-01",
    )

    agent.add_outage(
        asset_id=alpha.asset_id,
        start="2026-09-20",
        end=None,
        outage_type="PLANNED_MAINTENANCE",
        cause_state="OFFICIALLY_REPORTED",
        reported_cause="Scheduled inverter maintenance",
        capacity_impact_mw=50,
        evidence_ids=[ev_reg.evidence_id],
    )

    agent.add_dependency(
        asset_id=alpha.asset_id,
        dependency_type="EQUIPMENT",
        counterparty="InverterVendor A",
        detail="Public project documentation indicates inverter supply",
        evidence_ids=[ev_util.evidence_id],
    )

    agent.add_demand_observation(
        region="North",
        peak_demand_mw=450,
        unit="MW",
        observed_at="2026-09-01",
        evidence_id=ev_reg.evidence_id,
    )

    result = agent.analyze(as_of="2026-10-09")
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    demo()