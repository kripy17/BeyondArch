import asyncio
import json
import shlex

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from app.services.network_traffic import analyze_pcap
from app.services.nmap_runner import (
    ALLOWED_SCAN_MODES,
    build_nmap_argv,
    target_is_private_or_local,
)
from app.services.parser import normalize_target

router = APIRouter()

MAX_PCAP_SIZE = 25 * 1024 * 1024
NMAP_STREAM_TIMEOUT_SECONDS = 120


@router.post("/pcap/analyze")
async def pcap_analyze(file: UploadFile = File(...)):
    chunks = []
    received = 0
    while True:
        chunk = await file.read(1024 * 1024)
        if not chunk:
            break
        received += len(chunk)
        if received > MAX_PCAP_SIZE:
            raise HTTPException(status_code=413, detail="PCAP too large. Limit is 25 MB for MVP.")
        chunks.append(chunk)

    data = b"".join(chunks)
    if not data:
        raise HTTPException(status_code=400, detail="Uploaded PCAP is empty.")

    return analyze_pcap(file.filename or "uploaded.pcap", data)


class NmapStreamRequest(BaseModel):
    target: str = Field(..., min_length=3, max_length=1000)
    mode: str = "quick_tcp"
    confirm_permission: bool = False
    allow_private: bool = False


@router.post("/nmap/stream")
async def nmap_stream(request: NmapStreamRequest):
    if not request.confirm_permission:
        raise HTTPException(
            status_code=400,
            detail="You must confirm that you own or have permission to scan this target.",
        )

    normalized = normalize_target(request.target)
    hostname = normalized.get("hostname")
    if not hostname:
        raise HTTPException(status_code=400, detail="A resolvable domain or IP target is required.")

    if target_is_private_or_local(hostname) and not request.allow_private:
        raise HTTPException(
            status_code=400,
            detail="Private/local targets are blocked unless local mode is enabled.",
        )

    try:
        argv = build_nmap_argv(hostname, request.mode)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "Invalid scan mode.",
                "allowed_modes": sorted(ALLOWED_SCAN_MODES.keys()),
            },
        )

    command_display = shlex.join(argv)

    async def event_generator():
        yield f"data: {json.dumps({'type': 'start', 'command': command_display})}\n\n"

        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        timed_out = False
        loop = asyncio.get_running_loop()
        deadline = loop.time() + NMAP_STREAM_TIMEOUT_SECONDS
        try:
            while True:
                budget = deadline - loop.time()
                if budget <= 0:
                    timed_out = True
                    break
                try:
                    line = await asyncio.wait_for(proc.stdout.readline(), timeout=budget)
                except asyncio.TimeoutError:
                    timed_out = True
                    break
                if not line:
                    break
                text = line.decode(errors="replace").rstrip()
                if text:
                    yield f"data: {json.dumps({'type': 'stdout', 'line': text})}\n\n"
        finally:
            if timed_out and proc.returncode is None:
                proc.kill()
            await proc.wait()

        if timed_out:
            yield f"data: {json.dumps({'type': 'error', 'message': f'Scan aborted after {NMAP_STREAM_TIMEOUT_SECONDS}s timeout.'})}\n\n"
        elif proc.returncode != 0:
            stderr = (await proc.stderr.read()).decode(errors="replace")[:2000]
            yield f"data: {json.dumps({'type': 'error', 'message': stderr})}\n\n"
        else:
            yield f"data: {json.dumps({'type': 'done', 'returncode': proc.returncode})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )
