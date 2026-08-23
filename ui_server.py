import os
import sys

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent
from pydantic import BaseModel

app = FastAPI()

class ToolRequest(BaseModel):
    tool_name: str
    arguments: dict

async def call_mcp_tool(tool_name: str, arguments: dict):
    server_script = os.path.join(os.path.dirname(__file__), "server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_script]
    )
    async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:  # type: ignore
        await session.initialize()
        result = await session.call_tool(tool_name, arguments=arguments)
        # result.content can contain various types, we extract text from TextContent objects
        return [c.text for c in result.content if isinstance(c, TextContent)]

@app.post("/api/execute")
async def execute(req: ToolRequest):
    try:
        content = await call_mcp_tool(req.tool_name, req.arguments)
        return {"success": True, "content": content}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}

# Mount the existing frontend
frontend_dir = os.path.join(os.path.dirname(__file__), "user-facing-ui")
app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="static")

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
