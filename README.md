# MCPShield - Baseline Server

This is a minimal, unhardened Model Context Protocol (MCP) filesystem server designed as a test fixture for the MCPShield defense middleware.

**Note: This component has no input validation by design and is meant to sit behind the MCPShield middleware in a later phase.**

## Running the Server Standalone
You can run the server directly (using stdio transport):
```bash
python server.py
```

## Running the Test Client
The test client runs the server as a subprocess, calls the tools with valid arguments, and runs a path traversal test case.
```bash
pip install -r requirements.txt
python client.py
```
