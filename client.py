import asyncio
import os
import sys
import warnings

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

# Suppress annoying Pydantic/FastMCP warnings printed to stderr
warnings.filterwarnings("ignore")

async def main():
    server_script = os.path.join(os.path.dirname(__file__), "server.py")
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[server_script]
    )

    async with stdio_client(server_params) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        
        print("--- list_tools() ---")
        tools = await session.list_tools()
        print(tools)
            
        print("\n--- Valid Operations ---")
        test_dir = "test_dir"
        print("create_directory:")
        print(await session.call_tool("create_directory", arguments={"path": test_dir}))
        
        print("\nlist_directory (root):")
        print(await session.call_tool("list_directory", arguments={"path": ""}))
        
        test_file = os.path.join(test_dir, "test.txt")
        print("\nwrite_file:")
        print(await session.call_tool("write_file", arguments={"path": test_file, "content": "hello world"}))
        
        print("\nread_file:")
        print(await session.call_tool("read_file", arguments={"path": test_file}))

        print("\n--- ..-path Test Case (ASR Baseline) ---")
        # Create a file outside the sandbox to read (only if it doesn't exist to avoid breaking UI demo)
        out_of_sandbox_file = os.path.join(os.path.dirname(__file__), "secret.txt")
        if not os.path.exists(out_of_sandbox_file):
            with open(out_of_sandbox_file, "w", encoding="utf-8") as f:  # noqa: ASYNC230
                f.write("top secret")
            
        traversal_path = "../secret.txt"
        try:
            result = await session.call_tool("read_file", arguments={"path": traversal_path})
            print("Read succeeded! Output:", result)
        except Exception as e:  # noqa: BLE001
            print("Read was blocked:", e)
            
        # Intentionally NOT cleaning up secret.txt so that the UI can use it!

if __name__ == "__main__":
    asyncio.run(main())
