from fastmcp import FastMCP
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