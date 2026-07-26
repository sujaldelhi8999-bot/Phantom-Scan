import json
from html import escape
from typing import Any

from fastapi import APIRouter, HTTPException, Request, Response, WebSocket, status
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel, Field

from app.lab import (
    FAKE_USERS,
    LAB_SCENARIOS,
    is_vulnerable,
    lab_manifest,
    render_dashboard,
    scenario_status,
    set_many_scenario_states,
    set_scenario_state,
)

router = APIRouter(tags=["phantombank-lab"])


class LabScenarioRequest(BaseModel):
    state: str | None = Field(default=None, pattern="^(VULNERABLE|PATCHED|vulnerable|patched)$")
    scenario: str | None = None
    states: dict[str, str] = Field(default_factory=dict)


def lab_headers() -> dict[str, str]:
    headers: dict[str, str] = {"Cache-Control": "no-store"}
    if is_vulnerable("security_headers_cors"):
        headers["Access-Control-Allow-Origin"] = "*"
        headers["Access-Control-Allow-Credentials"] = "true"
        return headers
    headers.update(
        {
            "Content-Security-Policy": "default-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }
    )
    return headers


def html_response(content: str, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(content, status_code=status_code, headers=lab_headers())


def json_response(content: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(content, status_code=status_code, headers=lab_headers())


@router.get("/api/lab/status")
async def lab_status() -> dict[str, Any]:
    return {
        "name": "PhantomBank Lab",
        "default_state": "VULNERABLE",
        "scenario_state": scenario_status(),
        "scenarios": LAB_SCENARIOS,
    }


@router.post("/api/lab/scenario")
async def switch_lab_scenario(request: LabScenarioRequest) -> dict[str, Any]:
    try:
        if request.states:
            state = set_many_scenario_states(request.states)
        elif request.state:
            state = set_scenario_state(request.state, request.scenario)
        else:
            raise ValueError("Provide state or states")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    return {"scenario_state": state}


@router.post("/api/lab/reset")
async def reset_lab() -> dict[str, Any]:
    return {"scenario_state": set_scenario_state("VULNERABLE")}


@router.get("/api/lab/manifest")
async def api_lab_manifest(request: Request) -> dict[str, Any]:
    return lab_manifest(str(request.base_url).rstrip("/"))


@router.get("/lab/phantombank", response_class=HTMLResponse)
@router.get("/lab/phantombank/", response_class=HTMLResponse)
async def phantom_bank_home() -> HTMLResponse:
    return html_response(render_dashboard())


@router.get("/lab/phantombank/manifest")
async def phantom_bank_manifest(request: Request) -> dict[str, Any]:
    return lab_manifest(str(request.base_url).rstrip("/"))


@router.get("/lab/phantombank/login", response_class=HTMLResponse)
async def phantom_bank_login() -> HTMLResponse:
    content = """
    <html><body>
      <h1>PhantomBank Login</h1>
      <form action="/lab/phantombank/login" method="post">
        <input name="username" value="alice">
        <input name="password" type="password" value="demo-password">
        <button type="submit">Sign in</button>
      </form>
    </body></html>
    """
    response = html_response(content)
    if not is_vulnerable("authentication_rate_limiting_session"):
        response.headers["RateLimit-Limit"] = "5"
        response.headers["RateLimit-Remaining"] = "4"
        response.headers.append("Set-Cookie", "phantombank_session=demo; HttpOnly; Secure; SameSite=Lax; Path=/lab/phantombank")
    return response


@router.post("/lab/phantombank/login")
async def phantom_bank_login_post() -> JSONResponse:
    response = json_response({"status": "ok", "user": "alice", "training_only": True})
    if not is_vulnerable("authentication_rate_limiting_session"):
        response.headers["RateLimit-Limit"] = "5"
        response.headers.append("Set-Cookie", "phantombank_session=demo; HttpOnly; Secure; SameSite=Lax; Path=/lab/phantombank")
    return response


@router.get("/lab/phantombank/search", response_class=HTMLResponse)
async def phantom_bank_search(q: str = "") -> HTMLResponse:
    rendered = q if is_vulnerable("input_validation_output_encoding") else escape(q)
    return html_response(f"<html><body><h1>Search</h1><p>Results for {rendered}</p></body></html>")


@router.post("/lab/phantombank/api/profile")
async def update_profile(request: Request) -> JSONResponse:
    body = await safe_json(request)
    age = body.get("age")
    display_name = str(body.get("display_name", ""))
    if is_vulnerable("input_validation_output_encoding"):
        return json_response({"accepted": True, "message": f"accepted invalid input: {display_name or age}"})
    if not isinstance(age, int) or age < 18 or age > 120:
        return json_response({"accepted": False, "error": "age must be a realistic integer"}, 400)
    return json_response({"accepted": True, "display_name": escape(display_name)})


@router.get("/lab/phantombank/api/accounts")
async def accounts(customer: str = "alice") -> JSONResponse:
    if is_vulnerable("access_control_api") and "PHANTOMSCAN_DATA_PROBE" in customer:
        return json_response({"error": "demo data layer error near controlled marker", "marker": "PHANTOMSCAN_DATA_PROBE"}, 500)
    account = FAKE_USERS.get(customer, FAKE_USERS["alice"])
    return json_response({"account": account, "training_only": True})


@router.options("/lab/phantombank/api/accounts")
@router.options("/lab/phantombank/api/transfer")
async def api_options() -> Response:
    allow = "GET, POST, PUT, DELETE, OPTIONS" if is_vulnerable("access_control_api") else "GET, POST, OPTIONS"
    return Response(status_code=204, headers={**lab_headers(), "Allow": allow})


@router.get("/lab/phantombank/api/admin/users")
async def admin_users() -> JSONResponse:
    if is_vulnerable("access_control_api"):
        return json_response({"users": list(FAKE_USERS.values()), "note": "fake admin data"})
    return json_response({"error": "admin authentication required"}, 403)


@router.get("/lab/phantombank/transfer", response_class=HTMLResponse)
async def transfer_page() -> HTMLResponse:
    return html_response(render_dashboard())


@router.post("/lab/phantombank/api/transfer")
async def transfer(request: Request) -> JSONResponse:
    body = await safe_json(request)
    amount = parse_amount(body.get("amount"))
    if is_vulnerable("business_logic") and amount <= 0:
        return json_response({"accepted": True, "message": "demo transfer accepted with invalid amount"})
    if amount <= 0:
        return json_response({"accepted": False, "error": "amount must be positive"}, 400)
    if is_vulnerable("csrf") and not request.headers.get("x-csrf-token"):
        return json_response({"accepted": True, "message": "demo transfer accepted without CSRF token"})
    if not request.headers.get("x-csrf-token"):
        return json_response({"accepted": False, "error": "csrf token required"}, 403)
    return json_response({"accepted": True, "training_only": True})


@router.get("/lab/phantombank/upload", response_class=HTMLResponse)
async def upload_page() -> HTMLResponse:
    extra = "<p>Filenames are stored as provided in this vulnerable scenario.</p>" if is_vulnerable("file_handling_path_handling") else "<p>Filenames are normalized and validated.</p>"
    return html_response(
        f"""
        <html><body><h1>Upload Statement</h1>{extra}
        <form action="/lab/phantombank/upload" method="post" enctype="multipart/form-data">
          <input type="file" name="statement">
          <input name="filename" value="statement.pdf">
          <button type="submit">Upload</button>
        </form></body></html>
        """
    )


@router.post("/lab/phantombank/upload")
async def upload_simulation(request: Request) -> JSONResponse:
    body = await safe_json(request)
    filename = str(body.get("filename") or request.query_params.get("filename") or "statement.pdf")
    if is_vulnerable("file_handling_path_handling") and (".." in filename or filename.endswith(".html")):
        return json_response({"accepted": True, "stored_as": filename, "training_only": True})
    if ".." in filename or filename.endswith(".html"):
        return json_response({"accepted": False, "error": "unsafe filename rejected"}, 400)
    return json_response({"accepted": True, "stored_as": "normalized-demo-statement.pdf"})


@router.get("/lab/phantombank/download")
async def download(file: str = "statement-alice.txt") -> PlainTextResponse:
    if is_vulnerable("file_handling_path_handling") and ".." in file:
        return PlainTextResponse(
            "PHANTOMBANK INTERNAL DEMO STATEMENT\nAlice -> Bob: $10.00\nNo real files were read.",
            headers=lab_headers(),
        )
    if ".." in file or file.startswith("/"):
        return PlainTextResponse("unsafe path rejected", status_code=400, headers=lab_headers())
    return PlainTextResponse("Alice demo statement: $10.00 training transaction", headers=lab_headers())


@router.post("/lab/phantombank/graphql")
async def graphql(request: Request) -> JSONResponse:
    body = await safe_json(request)
    query = str(body.get("query", ""))
    if "__schema" in query and is_vulnerable("graphql"):
        return json_response({"data": {"__schema": {"queryType": {"name": "Query"}, "types": [{"name": "DemoAccount"}]}}})
    if "__schema" in query:
        return json_response({"errors": [{"message": "introspection disabled in lab patched mode"}]}, 403)
    return json_response({"data": {"viewer": "alice"}})


@router.get("/lab/phantombank/redirect")
async def redirect(next: str = "/lab/phantombank") -> Response:
    if is_vulnerable("redirect"):
        return RedirectResponse(next, status_code=302, headers=lab_headers())
    if next.startswith("/lab/phantombank") and not next.startswith("//"):
        return RedirectResponse(next, status_code=302, headers=lab_headers())
    return json_response({"error": "external redirect rejected"}, 400)


@router.get("/lab/phantombank/api/session")
async def session() -> JSONResponse:
    if is_vulnerable("authentication_rate_limiting_session"):
        return json_response(
            {
                "token": "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSIsImxhYiI6dHJ1ZX0.demoSignature",
                "token_config": {"alg": "none", "storage": "localStorage"},
            }
        )
    response = json_response({"session": "cookie", "token_config": {"alg": "RS256", "storage": "HttpOnly cookie"}})
    response.headers.append("Set-Cookie", "phantombank_session=demo; HttpOnly; Secure; SameSite=Lax; Path=/lab/phantombank")
    return response


@router.get("/lab/phantombank/api/debug")
async def debug() -> JSONResponse:
    if is_vulnerable("sensitive_exposure"):
        return json_response(
            {
                "debug": True,
                "api_key": "DEMO_KEY_DO_NOT_USE_123456",
                "note": "fake lab diagnostic data only",
            }
        )
    return json_response({"error": "debug endpoint disabled"}, 404)


@router.websocket("/lab/phantombank/ws/prices")
async def prices_websocket(websocket: WebSocket) -> None:
    if not is_vulnerable("websocket_exposure"):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    await websocket.send_text(json.dumps({"symbol": "PHB-DEMO", "price": "101.25", "training_only": True}))
    await websocket.close(code=1000)


async def safe_json(request: Request) -> dict[str, Any]:
    try:
        data = await request.json()
    except Exception:
        return dict(request.query_params)
    return data if isinstance(data, dict) else {}


def parse_amount(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0
