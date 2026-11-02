from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.services.cyber_utils import (
    base64_decode,
    base64_encode,
    calculate_entropy,
    convert_timestamp,
    decode_jwt,
    defang_indicators,
    parse_url,
    powershell_encoded_command,
    refang_indicators,
    sniff_magic_bytes,
    url_decode,
    url_encode,
    xor_brute_force,
)

router = APIRouter()


class TextRequest(BaseModel):
    text: str = Field(..., min_length=1)


class Base64Request(BaseModel):
    text: str = Field(..., min_length=1)
    action: Literal["encode", "decode"] = "decode"


class UrlCodecRequest(BaseModel):
    text: str = Field(..., min_length=1)
    action: Literal["encode", "decode"] = "decode"


class UrlParseRequest(BaseModel):
    url: str = Field(..., min_length=1)


class JwtDecodeRequest(BaseModel):
    token: str = Field(..., min_length=1)


class TimestampRequest(BaseModel):
    value: str = Field(..., min_length=1)


class EntropyRequest(BaseModel):
    text: str = Field(..., min_length=1)


class XorBruteforceRequest(BaseModel):
    ciphertext: str = Field(..., min_length=1)
    top_k: int = Field(5, ge=1, le=50)
    known_plaintext: str | None = None


class MagicBytesRequest(BaseModel):
    data: str = Field(..., min_length=1)


class PowershellCodecRequest(BaseModel):
    text: str = Field(..., min_length=1)
    action: Literal["encode", "decode"] = "decode"


class IndicatorDefangRequest(BaseModel):
    text: str = Field(..., min_length=1)


@router.post("/base64")
def base64_endpoint(request: Base64Request):
    if request.action == "encode":
        return base64_encode(request.text)

    return base64_decode(request.text)


@router.post("/url-codec")
def url_codec_endpoint(request: UrlCodecRequest):
    if request.action == "encode":
        return url_encode(request.text)

    return url_decode(request.text)


@router.post("/url-parse")
def url_parse_endpoint(request: UrlParseRequest):
    return parse_url(request.url)


@router.post("/jwt/decode")
def jwt_decode_endpoint(request: JwtDecodeRequest):
    return decode_jwt(request.token)


@router.post("/timestamp/convert")
def timestamp_convert_endpoint(request: TimestampRequest):
    return convert_timestamp(request.value)


@router.post("/entropy")
def entropy_endpoint(request: EntropyRequest):
    return calculate_entropy(request.text)


@router.post("/xor-bruteforce")
def xor_bruteforce_endpoint(request: XorBruteforceRequest):
    return {
        "results": xor_brute_force(
            ciphertext=request.ciphertext,
            top_k=request.top_k,
            known_plaintext=request.known_plaintext,
        )
    }


@router.post("/magic-bytes")
def magic_bytes_endpoint(request: MagicBytesRequest):
    return sniff_magic_bytes(request.data)


@router.post("/powershell-codec")
def powershell_codec_endpoint(request: PowershellCodecRequest):
    return powershell_encoded_command(request.text, action=request.action)


@router.post("/defang")
def defang_endpoint(request: IndicatorDefangRequest):
    return defang_indicators(request.text)


@router.post("/refang")
def refang_endpoint(request: IndicatorDefangRequest):
    return refang_indicators(request.text)

