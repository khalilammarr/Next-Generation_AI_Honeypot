from core.config import FAST_SCANNER_MODE, LLM_MAX_TOKENS, MAX_RESPONSE_CHARS


def classify_request(path: str, method: str, user_agent: str) -> str:
    lowered_path = path.lower()
    lowered_ua = (user_agent or "").lower()

    if method == "POST" and (lowered_path.startswith("/login") or lowered_path.startswith("/admin")):
        return "auth_probe"

    if any(term in lowered_path for term in [".env", ".git", "wp-config", "backup", "phpmyadmin", "adminer"]):
        return "sensitive_scan"

    if any(tool in lowered_ua for tool in ["nikto", "sqlmap", "gobuster", "dirbuster", "wfuzz", "nuclei", "masscan", "nmap"]):
        return "automated_scan"

    return "generic_probe"


def cache_key(path: str, method: str, user_agent: str) -> str:
    ua_family = (user_agent or "unknown").split("/")[0].lower()[:40]
    return f"{method}:{path}:{ua_family}"


def fallback_html(path: str, classification: str) -> str:
    if classification == "auth_probe":
        return (
            "<html><head><title>Sign In - Internal Portal</title></head>"
            "<body><h2>Authentication Service</h2><p>Invalid credentials.</p></body></html>"
        )

    if classification == "sensitive_scan":
        return (
            "<html><head><title>403 Forbidden</title></head>"
            "<body><h1>Forbidden</h1><p>You do not have permission to access this resource.</p></body></html>"
        )

    if path.endswith("robots.txt"):
        return "User-agent: *\nDisallow: /admin\nDisallow: /backup\n"

    if path.endswith("sitemap.xml"):
        return "<?xml version=\"1.0\" encoding=\"UTF-8\"?><urlset></urlset>"

    if path.endswith(".php"):
        return "<html><body><h1>500 Internal Server Error</h1></body></html>"

    return (
        "<html><head><title>404 Not Found</title></head>"
        "<body><h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>"
    )


def token_budget(classification: str) -> int:
    if classification == "auth_probe":
        return min(220, LLM_MAX_TOKENS)

    if classification in ["sensitive_scan", "automated_scan"]:
        return min(300, LLM_MAX_TOKENS)

    return min(420, LLM_MAX_TOKENS)


def sanitize_response(content: str) -> str:
    text = (content or "").strip()

    if text.startswith("```"):
        text = text.replace("```html", "").replace("```", "").strip()

    if len(text) > MAX_RESPONSE_CHARS:
        text = text[:MAX_RESPONSE_CHARS]

    return text


def should_skip_llm(path: str, classification: str) -> bool:
    lowered_path = path.lower()

    if lowered_path in ["/", "/favicon.ico", "/robots.txt", "/sitemap.xml"]:
        return True

    if FAST_SCANNER_MODE and classification in ["automated_scan", "sensitive_scan"]:
        return True

    return False
