from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.services.hackingtool_service import get_categories, run_tool

router = APIRouter()


class RunToolRequest(BaseModel):
    category_id: str = Field(..., min_length=1)
    tool_id: str = Field(..., min_length=1)
    target: str = ""
    args: str = ""
    confirm_authorization: bool = False


@router.get("/categories")
def list_categories():
    return get_categories()


@router.post("/run")
def execute_tool(request: RunToolRequest):
    if not request.confirm_authorization:
        raise HTTPException(
            status_code=400,
            detail="You must confirm authorization before running an external tool.",
        )

    return run_tool(
        category_id=request.category_id,
        tool_id=request.tool_id,
        target=request.target,
        args=request.args,
    )
