import uuid
from fastapi import Request


async def session_cookie_middleware(request: Request, call_next):
    session_id = request.cookies.get("scan_session_id") or str(uuid.uuid4())
    request.state.scan_session_id = session_id
    response = await call_next(request)
    if request.cookies.get("scan_session_id") != session_id:
        response.set_cookie(
            key="scan_session_id",
            value=session_id,
            httponly=True,
            samesite="lax",
            max_age=60 * 60 * 24 * 30,
        )
    return response


def session_id_from_request(request: Request) -> str:
    return getattr(request.state, "scan_session_id", request.cookies.get("scan_session_id") or str(uuid.uuid4()))
