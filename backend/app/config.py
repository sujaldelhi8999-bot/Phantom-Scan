from functools import lru_cache
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
ROOT_DIR = BASE_DIR.parent

load_dotenv(BASE_DIR / ".env")
load_dotenv(ROOT_DIR / ".env")


def env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, str(default)))
    except ValueError:
        return default


class Settings:
    app_name = "PhantomScan API"
    database_url = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'phantomscan.db'}")
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
    cors_origins = list(dict.fromkeys([frontend_url, "http://localhost:5173", "http://127.0.0.1:5173"]))
    openrouter_api_key = os.getenv("OPENROUTER_API_KEY", "")
    openrouter_model = os.getenv("OPENROUTER_MODEL", "openrouter/free")
    ai_max_modules = env_int("AI_MAX_MODULES", 10)
    ai_poc_max_per_scan = env_int("AI_POC_MAX_PER_SCAN", 5)
    exploit_sandbox = os.getenv("EXPLOIT_SANDBOX", "auto")
    exploit_docker_image = os.getenv("EXPLOIT_DOCKER_IMAGE", "python:3.12-slim")
    nvd_api_key = os.getenv("NVD_API_KEY", "")
    notification_webhook_url = os.getenv("PHANTOMSCAN_WEBHOOK_URL", "")
    self_audit_webhook = os.getenv("SELF_AUDIT_WEBHOOK", "http://localhost:8000/api/logs/alert")
    admin_username = os.getenv("ADMIN_USERNAME")
    admin_password = os.getenv("ADMIN_PASSWORD")
    secret_key = os.getenv("SECRET_KEY")
    local_user_id = os.getenv("LOCAL_USER_ID", "local-user")
    local_user_role = os.getenv("LOCAL_USER_ROLE", "user")
    verification_ttl_days = env_int("VERIFICATION_TTL_DAYS", 30)
    verification_challenge_minutes = env_int("VERIFICATION_CHALLENGE_MINUTES", 60)
    max_scan_duration = env_int("MAX_SCAN_DURATION", 300)
    max_requests_per_second = env_float("MAX_REQUESTS_PER_SECOND", 2.0)
    max_total_requests = env_int("MAX_TOTAL_REQUESTS", 300)
    max_concurrent_scans = env_int("MAX_CONCURRENT_SCANS", 2)
    max_redirect_depth = env_int("MAX_REDIRECT_DEPTH", 0)
    max_response_size = env_int("MAX_RESPONSE_SIZE", 1_048_576)
    browser_page_limit = env_int("BROWSER_PAGE_LIMIT", 8)
    active_target_allowlist = os.getenv("ACTIVE_TARGET_ALLOWLIST", "")
    deep_port_scan_enabled = os.getenv("DEEP_PORT_SCAN", "1") not in ("0", "false", "False")
    port_scan_concurrency = env_int("PORT_SCAN_CONCURRENCY", 64)
    port_scan_max_ports = env_int("PORT_SCAN_MAX_PORTS", 1024)
    port_scan_sweep_timeout = env_float("PORT_SCAN_SWEEP_TIMEOUT", 75.0)

    # GitHub OAuth
    github_client_id = os.getenv("GITHUB_CLIENT_ID", "")
    github_client_secret = os.getenv("GITHUB_CLIENT_SECRET", "")
    github_redirect_uri = os.getenv("GITHUB_REDIRECT_URI", "")

    # GitHub App
    github_app_id = os.getenv("GITHUB_APP_ID", "")
    github_app_private_key = os.getenv("GITHUB_APP_PRIVATE_KEY", "")
    github_webhook_secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")

    # Supabase Auth (Google / GitHub login)
    supabase_url = os.getenv("SUPABASE_URL", "")
    supabase_jwt_secret = os.getenv("SUPABASE_JWT_SECRET", "")
    supabase_admin_emails = os.getenv("SUPABASE_ADMIN_EMAILS", "")


@lru_cache
def get_settings() -> Settings:
    return Settings()
