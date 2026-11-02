import re
import time
from typing import Any
from app.utils import utc_now


def simulate_detection(
    rule_content: str,
    format_type: str,
    events: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Evaluates a detection rule (Sigma, YARA, or KQL) against an array of structured log events.
    Returns per-event match diagnostics, execution duration, and tuning recommendations.
    """
    start_time = time.perf_counter()
    format_type = format_type.lower().strip()

    tokens = _extract_rule_tokens(rule_content, format_type)
    exclusions = _extract_rule_exclusions(rule_content, format_type)

    results = []
    total_matches = 0
    false_positives = 0
    true_positives = 0

    for idx, ev in enumerate(events):
        ev_id = ev.get("id") or f"event-{idx + 1}"
        label = ev.get("label", "")
        expected = ev.get("expected", "match" if "malicious" in label.lower() or "attack" in label.lower() else "benign")

        event_text = ev.get("raw") or ev.get("event") or ""
        if not event_text:
            # Flatten dict fields into searchable string
            event_text = " ".join(f"{k}={v}" for k, v in ev.items() if k not in ["id", "label", "expected"])

        matched_tokens, is_hit = _evaluate_event(event_text, ev, tokens, exclusions, format_type)

        verdict = "no_match"
        if is_hit:
            total_matches += 1
            if expected == "match":
                verdict = "tp"
                true_positives += 1
            else:
                verdict = "fp"
                false_positives += 1
        else:
            if expected == "match":
                verdict = "fn"
            else:
                verdict = "tn"

        results.append({
            "id": ev_id,
            "label": label or f"Sample #{idx + 1}",
            "expected": expected,
            "hit": is_hit,
            "matched_tokens": matched_tokens,
            "verdict": verdict,
            "event_snippet": event_text[:200] + ("..." if len(event_text) > 200 else ""),
        })

    duration_ms = round((time.perf_counter() - start_time) * 1000, 3)

    # Automated false positive tuning recommendation
    tuning_suggestions = []
    if false_positives > 0:
        for r in results:
            if r["verdict"] == "fp":
                tuning_suggestions.append({
                    "event_id": r["id"],
                    "suggestion": f"Exclude benign noise with filter condition for '{r['label']}'",
                    "filter_snippet": f"filter:\n  - CommandLine|contains: '{r['matched_tokens'][0] if r['matched_tokens'] else 'benign'}'\ncondition: selection and not filter",
                })

    precision = round(true_positives / (true_positives + false_positives), 3) if (true_positives + false_positives) > 0 else 0.0

    return {
        "format": format_type,
        "evaluated_at": utc_now(),
        "duration_ms": duration_ms,
        "total_events": len(events),
        "total_matches": total_matches,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "precision": precision,
        "extracted_tokens": tokens,
        "exclusions": exclusions,
        "results": results,
        "tuning_suggestions": tuning_suggestions,
    }


def _extract_rule_tokens(rule_content: str, fmt: str) -> list[str]:
    tokens = []
    if fmt == "sigma":
        for line in rule_content.splitlines():
            line = line.strip()
            # Match list items or field values under detection/selection
            m = re.match(r"^-\s*['\"]?([^'\"#\n]+)['\"]?", line)
            if m:
                token = m.group(1).strip()
                if token and not token.startswith("attack."):
                    tokens.append(token)
            m_val = re.search(r":\s*['\"]([^'\"]+)['\"]", line)
            if m_val:
                raw_token = m_val.group(1).strip()
                if not raw_token.startswith("attack."):
                    clean = raw_token.replace("\\\\", "\\").lstrip("\\/")
                    if len(clean) >= 2:
                        tokens.append(clean)
    elif fmt == "yara":
        for line in rule_content.splitlines():
            m = re.search(r"\$[a-zA-Z0-9_]+\s*=\s*\"([^\"]+)\"", line)
            if m:
                tokens.append(m.group(1).strip())
    elif fmt == "kql":
        for line in rule_content.splitlines():
            m = re.findall(r"\"([^\"]+)\"", line)
            for s in m:
                tokens.append(s.strip())
            m_has = re.findall(r"has_any\(([^)]+)\)", line)
            for s in m_has:
                for item in s.split(","):
                    clean = item.strip().strip('"').strip("'")
                    if clean:
                        tokens.append(clean)

    # Fallback to key terms if none extracted
    if not tokens:
        words = [w for w in re.findall(r"\b[A-Za-z0-9_.-]{3,}\b", rule_content) if w.lower() not in ["title", "id", "status", "logsource", "detection", "condition", "level", "rule", "meta", "strings", "where", "project"]]
        tokens = words[:4]

    return list(dict.fromkeys(tokens))


def _extract_rule_exclusions(rule_content: str, fmt: str) -> list[str]:
    exclusions = []
    if fmt == "sigma":
        in_filter = False
        for line in rule_content.splitlines():
            if re.search(r"^\s*filter\w*:", line):
                in_filter = True
                continue
            if in_filter and re.search(r"^\s*(selection|condition):", line):
                in_filter = False
            if in_filter:
                m = re.findall(r"['\"]([^'\"]+)['\"]", line)
                exclusions.extend(m)
    return list(dict.fromkeys(exclusions))


def _evaluate_event(
    event_text: str,
    event_dict: dict[str, Any],
    tokens: list[str],
    exclusions: list[str],
    fmt: str,
) -> tuple[list[str], bool]:
    matched_tokens = []
    text_lower = event_text.lower()

    # Check exclusions first
    for ex in exclusions:
        if ex.lower() in text_lower:
            return ([], False)

    for tok in tokens:
        if tok.lower() in text_lower:
            matched_tokens.append(tok)

    # Rule hit condition
    if fmt == "sigma":
        is_hit = len(matched_tokens) >= min(len(tokens), 2) if len(tokens) >= 2 else len(matched_tokens) > 0
    elif fmt == "yara":
        is_hit = len(matched_tokens) == len(tokens) if tokens else False
    else:  # kql
        is_hit = len(matched_tokens) >= 1

    return (matched_tokens, is_hit)
