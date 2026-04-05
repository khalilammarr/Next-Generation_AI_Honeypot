"""
Semantic MIME-Type Router.
Maps attacker-requested file extensions to correct Content-Type headers
and provides format hints to the LLM so it generates the right format.
"""

MIME_MAP = {
    ".html": "text/html",
    ".htm":  "text/html",
    ".php":  "text/html",
    ".asp":  "text/html",
    ".jsp":  "text/html",
    ".sql":  "text/plain; charset=utf-8",
    ".env":  "text/plain; charset=utf-8",
    ".txt":  "text/plain; charset=utf-8",
    ".log":  "text/plain; charset=utf-8",
    ".cfg":  "text/plain; charset=utf-8",
    ".ini":  "text/plain; charset=utf-8",
    ".conf": "text/plain; charset=utf-8",
    ".bak":  "text/plain; charset=utf-8",
    ".json": "application/json",
    ".xml":  "application/xml",
    ".csv":  "text/csv",
    ".gz":   "application/gzip",
    ".zip":  "application/zip",
    ".tar":  "application/x-tar",
}


def resolve_mime(path: str) -> str:
    """Return the correct MIME type based on file extension."""
    lowered = path.lower()
    for ext, mime in MIME_MAP.items():
        if lowered.endswith(ext):
            return mime
    return "text/html"


def build_format_hint(path: str) -> str:
    """
    Give the LLM a format directive based on the requested file extension.
    This prevents it from wrapping SQL dumps in HTML tags, etc.
    """
    lowered = path.lower()

    if lowered.endswith((".sql", ".bak")):
        return "FORMAT: raw MySQL dump with CREATE TABLE and INSERT statements. NO HTML. NO markdown."
    if lowered.endswith((".env", ".cfg", ".ini", ".conf")):
        return "FORMAT: raw KEY=VALUE configuration file. NO HTML. NO markdown."
    if lowered.endswith(".json"):
        return "FORMAT: raw JSON object or array. NO HTML. NO markdown."
    if lowered.endswith(".xml"):
        return "FORMAT: raw XML document with proper tags. NO HTML wrapping."
    if lowered.endswith(".log"):
        return "FORMAT: raw log lines with timestamps, one per line. NO HTML."
    if lowered.endswith(".txt"):
        return "FORMAT: raw text file containing sensible or confidential information like passwords, API keys, or private notes. NO HTML."
    if lowered.endswith((".gz", ".zip", ".tar")):
        return "FORMAT: HTML error page saying 'Binary download requires authentication.'"
    if lowered.endswith(".csv"):
        return "FORMAT: raw CSV data with header row. NO HTML."
    if lowered.endswith((".php", ".asp", ".jsp")):
        return "FORMAT: rendered HTML output as if the script executed. Show a realistic web page."

    return "FORMAT: realistic HTML page with proper tags."
