"""tmcheck: a checker for threat models kept as YAML in the repository.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re
import yaml


class ModelError(Exception):
    """The file cannot be read as a threat model."""


@dataclass(frozen=True, order=True)
class Issue:
    ref: str          # id of the zone/element/flow/threat the issue is about
    code: str
    message: str = ""


@dataclass(frozen=True, order=True)
class Gap:
    ref: str          # element or flow id
    category: str     # one STRIDE letter


@dataclass(frozen=True)
class RankedThreat:
    id: str
    score: int
    level: str        # "high" | "medium" | "low"


VALID_KINDS = {"external_entity", "process", "data_store"}
VALID_STRIDE = {"S", "T", "R", "I", "D", "E"}
VALID_STATUSES = {"open", "mitigated", "accepted"}
STRIDE_ORDER = ["S", "T", "R", "I", "D", "E"]
ALLOWED_PROTOCOLS = {"https", "tls", "mtls", "sftp", "ssh"}


def _natural_key(text: str):
    """Splits string into a list of text and integers for natural sorting (e.g. T2 before T10)."""
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r'(\d+)', text)]


def load_model(path) -> dict:
    """Read the YAML file with yaml.safe_load and return the mapping.

    Missing or null `zones`, `elements`, `flows`, `threats` become []. Raise ModelError if the
    file cannot be read, is not valid YAML, uses a tag safe_load refuses, has a top level that
    is not a mapping, or has one of the four sections that is not a list.
    """
    file_path = Path(path)
    if not file_path.is_file():
        raise ModelError(f"File not found or cannot be read: {path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        raise ModelError(f"Failed to parse YAML file: {e}") from e

    if not isinstance(data, dict):
        raise ModelError("Top-level YAML structure must be a mapping (dict)")

    sections = ["zones", "elements", "flows", "threats"]
    for sec in sections:
        val = data.get(sec)
        if val is None:
            data[sec] = []
        elif not isinstance(val, list):
            raise ModelError(f"Section '{sec}' must be a list, got {type(val).__name__}")

    return data


def applicable(kind: str, *, is_log: bool = False) -> set[str]:
    """STRIDE per element: the categories that apply to `kind`. Unknown kind: ValueError."""
    if kind == "external_entity":
        return {"S", "R"}
    elif kind == "process":
        return {"S", "T", "R", "I", "D", "E"}
    elif kind == "data_store":
        cats = {"T", "I", "D"}
        if is_log:
            cats.add("R")
        return cats
    elif kind == "data_flow":
        return {"T", "I", "D"}
    else:
        raise ValueError(f"Unknown element kind: {kind}")


def validate(model: dict) -> list[Issue]:
    """Structural problems, sorted by (ref, code, message), no duplicates."""
    issues = []
    all_ids = {}
    elements, flows = {}, {}
    zones = {z["id"] for z in model.get("zones", []) if isinstance(z, dict) and "id" in z}

    def check_id(item_id):
        if item_id in all_ids:
            issues.append(Issue(ref=item_id, code="DUPLICATE_ID", message=f"Duplicate ID found: {item_id}"))
            return False
        return True

    # 1. Register Zones
    for z in model.get("zones", []):
        if isinstance(z, dict) and "id" in z:
            if check_id(z["id"]):
                all_ids[z["id"]] = "zone"

    # 2. Process Elements
    for elem in model.get("elements", []):
        if not isinstance(elem, dict) or "id" not in elem:
            continue
        e_id = elem["id"]
        if check_id(e_id):
            all_ids[e_id] = "element"
        elements[e_id] = elem

        if elem.get("kind") not in VALID_KINDS:
            issues.append(Issue(ref=e_id, code="BAD_KIND", message=f"Invalid element kind: {elem.get('kind')}"))
        if elem.get("zone") not in zones:
            issues.append(Issue(ref=e_id, code="UNKNOWN_ZONE", message=f"Unknown zone: {elem.get('zone')}"))

    # 3. Process Flows
    for flow in model.get("flows", []):
        if not isinstance(flow, dict) or "id" not in flow:
            continue
        f_id = flow["id"]
        if check_id(f_id):
            all_ids[f_id] = "flow"
        flows[f_id] = flow

        src = flow.get("source")
        tgt = flow.get("target")
        src_elem = elements.get(src)
        tgt_elem = elements.get(tgt)

        if src not in elements or tgt not in elements:
            issues.append(Issue(ref=f_id, code="UNKNOWN_REF", message=f"Flow references unknown element(s): {src}, {tgt}"))
        else:
            if src == tgt or (src_elem.get("kind") != "process" and tgt_elem.get("kind") != "process"):
                issues.append(Issue(ref=f_id, code="INVALID_FLOW", message="Invalid flow endpoint combination"))

    # 4. Process Threats
    for threat in model.get("threats", []):
        if not isinstance(threat, dict) or "id" not in threat:
            continue
        t_id = threat["id"]
        if check_id(t_id):
            all_ids[t_id] = "threat"

        target_id = threat.get("target")
        target_kind = None

        if target_id in elements:
            target_kind = elements[target_id].get("kind")
        elif target_id in flows:
            target_kind = "data_flow"
        else:
            issues.append(Issue(ref=t_id, code="UNKNOWN_REF", message=f"Threat target not found: {target_id}"))

        cat = threat.get("category")
        if cat not in VALID_STRIDE:
            issues.append(Issue(ref=t_id, code="BAD_CATEGORY", message=f"Invalid STRIDE category: {cat}"))
        elif target_kind:
            try:
                is_log = bool(elements[target_id].get("is_log", False)) if target_id in elements else False
                app_cats = applicable(target_kind, is_log=is_log)
                if cat not in app_cats:
                    issues.append(Issue(ref=t_id, code="INAPPLICABLE_CATEGORY", message=f"Category {cat} does not apply to {target_kind}"))
            except ValueError:
                pass

        for score_field in ("likelihood", "impact"):
            val = threat.get(score_field)
            if isinstance(val, bool) or not isinstance(val, int) or not (1 <= val <= 5):
                issues.append(Issue(ref=t_id, code="BAD_SCORE", message=f"Invalid {score_field}: {val}"))

        status = threat.get("status")
        if status not in VALID_STATUSES:
            issues.append(Issue(ref=t_id, code="BAD_STATUS", message=f"Invalid status: {status}"))
        elif status == "mitigated":
            mit = threat.get("mitigation")
            if not isinstance(mit, str) or not mit.strip():
                issues.append(Issue(ref=t_id, code="MISSING_MITIGATION", message="Mitigated threat requires mitigation text"))
        elif status == "accepted":
            just = threat.get("justification")
            if not isinstance(just, str) or not just.strip():
                issues.append(Issue(ref=t_id, code="MISSING_JUSTIFICATION", message="Accepted threat requires justification text"))

    unique_issues = set(issues)
    return sorted(unique_issues, key=lambda i: (i.ref, i.code, i.message))


def crossing_flows(model: dict) -> list[str]:
    """Ids of flows whose source and target are in different zones, in file order."""
    elements = {e["id"]: e for e in model.get("elements", []) if isinstance(e, dict) and "id" in e}
    result = []

    for flow in model.get("flows", []):
        if not isinstance(flow, dict) or "id" not in flow:
            continue
        src = flow.get("source")
        tgt = flow.get("target")

        if src in elements and tgt in elements:
            src_zone = elements[src].get("zone")
            tgt_zone = elements[tgt].get("zone")
            if src_zone and tgt_zone and src_zone != tgt_zone:
                result.append(flow["id"])

    return result


def coverage_gaps(model: dict) -> list[Gap]:
    """(ref, category) pairs in scope with no threat recorded, sorted by ref then S, T, R, I, D, E."""
    elements = {e["id"]: e for e in model.get("elements", []) if isinstance(e, dict) and "id" in e}
    flows = {f["id"]: f for f in model.get("flows", []) if isinstance(f, dict) and "id" in f}

    x_flows = crossing_flows(model)
    in_scope = set(x_flows)

    for f_id in x_flows:
        flow = flows.get(f_id)
        if flow:
            src = flow.get("source")
            tgt = flow.get("target")
            if src in elements:
                in_scope.add(src)
            if tgt in elements:
                in_scope.add(tgt)

    covered = set()
    for threat in model.get("threats", []):
        if isinstance(threat, dict):
            t_target = threat.get("target")
            t_cat = threat.get("category")
            if t_target and t_cat:
                covered.add((t_target, t_cat))

    gaps = []
    for item_id in in_scope:
        item_kind = None
        is_log = False

        if item_id in elements:
            item_kind = elements[item_id].get("kind")
            is_log = bool(elements[item_id].get("is_log", False))
        elif item_id in flows:
            item_kind = "data_flow"

        if not item_kind:
            continue

        try:
            app_cats = applicable(item_kind, is_log=is_log)
        except ValueError:
            continue

        for cat in STRIDE_ORDER:
            if cat in app_cats and (item_id, cat) not in covered:
                gaps.append(Gap(ref=item_id, category=cat))

    return sorted(gaps, key=lambda g: (g.ref, STRIDE_ORDER.index(g.category)))


def policy_findings(model: dict) -> list[Issue]:
    """UNENCRYPTED_CROSSING, UNAUTHENTICATED_INBOUND, PII_STORE_WITHOUT_I_THREAT, sorted by (ref, code)."""
    findings = []
    zones = {z["id"]: z.get("trust", 0) for z in model.get("zones", []) if isinstance(z, dict) and "id" in z}
    elements = {e["id"]: e for e in model.get("elements", []) if isinstance(e, dict) and "id" in e}
    flows = {f["id"]: f for f in model.get("flows", []) if isinstance(f, dict) and "id" in f}

    x_flows = crossing_flows(model)

    for f_id in x_flows:
        flow = flows.get(f_id)
        if not flow:
            continue

        proto = str(flow.get("protocol", "")).strip().lower()
        if proto not in ALLOWED_PROTOCOLS:
            findings.append(Issue(ref=f_id, code="UNENCRYPTED_CROSSING", message=f"Unencrypted protocol across zone boundary: {proto}"))

        src_id = flow.get("source")
        tgt_id = flow.get("target")
        if src_id in elements and tgt_id in elements:
            src_zone = elements[src_id].get("zone")
            tgt_zone = elements[tgt_id].get("zone")

            src_trust = zones.get(src_zone, 0)
            tgt_trust = zones.get(tgt_zone, 0)

            if tgt_trust > src_trust and flow.get("authenticated") is not True:
                findings.append(Issue(ref=f_id, code="UNAUTHENTICATED_INBOUND", message="Inbound flow to higher trust zone requires authentication"))

    i_threat_targets = {
        threat.get("target")
        for threat in model.get("threats", [])
        if isinstance(threat, dict) and threat.get("category") == "I"
    }

    for e_id, elem in elements.items():
        if elem.get("kind") == "data_store" and elem.get("holds_pii") is True:
            if e_id not in i_threat_targets:
                findings.append(Issue(ref=e_id, code="PII_STORE_WITHOUT_I_THREAT", message="Data store holding PII requires an Information Disclosure (I) threat"))

    return sorted(findings, key=lambda issue: (issue.ref, issue.code))


def rank(model: dict) -> list[RankedThreat]:
    """Open threats with valid scores, by score desc, then impact desc, then natural id order."""
    ranked = []

    for threat in model.get("threats", []):
        if not isinstance(threat, dict) or threat.get("status") != "open":
            continue

        l, i = threat.get("likelihood"), threat.get("impact")
        if isinstance(l, bool) or not isinstance(l, int) or not (1 <= l <= 5):
            continue
        if isinstance(i, bool) or not isinstance(i, int) or not (1 <= i <= 5):
            continue

        score = l * i
        if score >= 15:
            level = "high"
        elif score >= 8:
            level = "medium"
        else:
            level = "low"

        ranked.append((threat["id"], score, i, RankedThreat(id=threat["id"], score=score, level=level)))

    ranked.sort(key=lambda item: (-item[1], -item[2], _natural_key(item[0])))
    return [r[3] for r in ranked]

