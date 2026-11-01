import requests

MANIFEST_URL = "https://autonomous-contract-security.vercel.app/mcp/manifest"
REPO_URL = "https://github.com/inkbymuntaha-alt/autonomous-contract-security-mcp"

REGISTRY_ENDPOINTS = [
    "https://registry.modelcontextprotocol.io/v1/ping",
    "https://api.smithery.ai/v1/servers/register",
    "https://mcp.so/api/register"
]

def register_server():
    payload = {
        "manifest_url": MANIFEST_URL,
        "repository": REPO_URL,
        "name": "autonomous-contract-security",
        "x402_enabled": True
    }
    headers = {"Content-Type": "application/json"}
    
    for endpoint in REGISTRY_ENDPOINTS:
        try:
            res = requests.post(endpoint, json=payload, headers=headers, timeout=10)
            print(f"Ping sent to {endpoint} -> Status: {res.status_code}")
        except Exception as e:
            print(f"Could not reach {endpoint}: {e}")

if __name__ == "__main__":
    register_server()
