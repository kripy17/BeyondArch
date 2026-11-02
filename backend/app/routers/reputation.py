from collections import Counter

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.hash_analyzer import identify_hash
from app.services.parser import detect_target_type
from app.services.reputation import (
    analyze_domain_reputation,
    analyze_ip_reputation,
    analyze_url_reputation,
    enrich_indicator_reputation,
)

router = APIRouter()


class IpReputationRequest(BaseModel):
    ip: str = Field(..., min_length=1)


class DomainReputationRequest(BaseModel):
    domain: str = Field(..., min_length=1)


class UrlReputationRequest(BaseModel):
    url: str = Field(..., min_length=1)


class EnrichReputationRequest(BaseModel):
    indicator: str = Field(..., min_length=1)
    indicator_type: str = Field(..., min_length=1)


class BatchItem(BaseModel):
    value: str = Field(..., min_length=1, max_length=1000)
    indicator_type: str | None = None


class EnrichBatchRequest(BaseModel):
    indicators: list[BatchItem] = Field(..., min_length=1, max_length=25)


def _infer_indicator_type(value: str) -> str:
    hash_info = identify_hash(value.strip())
    if hash_info.get("valid"):
        return "hash"
    if "@" in value:
        return "email"
    if value.lower().startswith(("http://", "https://")):
        return "url"
    return detect_target_type(value)


@router.post("/ip")
def ip_reputation(request: IpReputationRequest):
    return analyze_ip_reputation(request.ip)


@router.post("/domain")
def domain_reputation(request: DomainReputationRequest):
    return analyze_domain_reputation(request.domain)


@router.post("/url")
def url_reputation(request: UrlReputationRequest):
    return analyze_url_reputation(request.url)


@router.post("/enrich")
async def enrich_reputation(request: EnrichReputationRequest):
    return await enrich_indicator_reputation(
        indicator=request.indicator,
        indicator_type=request.indicator_type,
    )


@router.post("/enrich-batch")
async def enrich_batch_reputation(request: EnrichBatchRequest):
    results = []
    skipped = []
    verdict_counts: Counter[str] = Counter()

    for index, item in enumerate(request.indicators):
        value = item.value.strip()
        indicator_type = (item.indicator_type or "").strip() or _infer_indicator_type(value)
        try:
            report = await enrich_indicator_reputation(indicator=value, indicator_type=indicator_type)
        except Exception as exc:
            skipped.append({
                "index": index,
                "reason": f"{type(exc).__name__} while enriching '{value[:80]}'.",
            })
            continue

        findings = report.get("findings", []) if isinstance(report, dict) else []
        for entry in findings:
            verdict = entry.get("verdict") if isinstance(entry, dict) else None
            if verdict:
                verdict_counts[verdict] += 1
        results.append(report)

    return {
        "results": results,
        "summary": {
            "requested": len(request.indicators),
            "processed": len(results),
            "skipped_count": len(skipped),
            "skipped": skipped,
            "verdict_counts": dict(verdict_counts),
            "note": (
                "Batch enrichment runs the same per-indicator checks as /api/reputation/enrich "
                "(cap 25). External provider lookups still require BEYONDLABS_VT_API_KEY and only "
                "apply to hash indicators; indicator types are auto-detected when not supplied."
            ),
        },
    }
