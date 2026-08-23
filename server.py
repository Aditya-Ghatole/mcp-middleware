import os
import warnings

warnings.filterwarnings("ignore")

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("MCPShield-Baseline")

ALLOWED_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "sandbox"))
os.makedirs(ALLOWED_ROOT, exist_ok=True)

# Intentional lack of input validation and canonicalization to allow path traversal 
# as a baseline for measuring Attack Success Rate (ASR) before middleware is applied.
def _resolve(path: str) -> str:
    return os.path.join(ALLOWED_ROOT, path)

@mcp.tool()
def read_file(path: str) -> str:
    with open(_resolve(path), "r", encoding="utf-8") as f:
        return f.read()

@mcp.tool()
def write_file(path: str, content: str) -> str:
    with open(_resolve(path), "w", encoding="utf-8") as f:
        f.write(content)
    return "OK"

@mcp.tool()
def list_directory(path: str) -> list[str]:
    return os.listdir(_resolve(path))

@mcp.tool()
def create_directory(path: str) -> str:
    os.makedirs(_resolve(path), exist_ok=True)
    return "OK"

if __name__ == "__main__":
    mcp.run(transport='stdio')
