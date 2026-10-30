
import json
from pathlib import Path
from fastmcp import FastMCP
from datetime import datetime, timedelta

mcp = FastMCP("SentinelMCP")

@mcp.tool()
def analyze_login(username: str, success: bool) -> dict:
    """Analyze a login attempt for suspicious activity."""

    if success:
        risk ="low"
        finding = "Successful login."

    else: 
        risk = "medium"
        finding = "Failed login attempt detected."

    return {
        "username": username,
        "risk_level": risk,
        "finding": finding
    }

@mcp.tool()
def read_login_logs() -> dict:
    """Read synthetic authentication events from a local JSON file."""

    log_path = Path(__file__).resolve().parent / "sample_logins.json"

    with log_path.open("r", encoding="utf-8") as file:
        events = json.load(file)

    return{
            "total_events": len(events),
            "events": events
        }

@mcp.tool()
def detect_brute_force() -> dict:
    """Detect repeated failed login attempts that may indicate a brute force attack with the same IP and username."""

    threshold = 5
    window_minutes = 5 
    log_data = read_login_logs()
    events = log_data["events"]

    failed_events = [
        event for event in events
        if event["success"] is False
    ]
    grouped_events = {}
    for event in failed_events:
        username = event["username"]
        source_ip = event["source_ip"]
        key = (username, source_ip)
        if key not in grouped_events:
            grouped_events[key] = []

        grouped_events[key].append(event)

    findings = []

    for key, attempts in grouped_events.items():
        attempts.sort(key=lambda x: datetime.fromisoformat(x["timestamp"]))

        for event in attempts:
            event_time = datetime.fromisoformat(event["timestamp"])
            window_start = event_time - timedelta(minutes=window_minutes)
            recent_attempts = [
                e for e in attempts
                if window_start <= datetime.fromisoformat(e["timestamp"]) <= event_time
            ]

            if len(recent_attempts) >= threshold:
                findings.append({
                    "username": key[0],
                    "source_ip": key[1],
                    "failed_attempts": len(recent_attempts),
                    "time_window": f"{window_start.isoformat()} to {event_time.isoformat()}",
                    "finding": "Potential brute force attack detected."
                })
                break

    return {
        "total_findings": len(findings),
        "findings": findings
    }