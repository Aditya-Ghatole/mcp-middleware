import os
from pathlib import Path

def process_file(filepath: Path):
    if not filepath.is_file(): return
    if filepath.name == 'uv.lock': return
    if filepath.suffix in ['.pyc', '.pdf', '.png', '.db']: return
    
    try:
        content = filepath.read_text(encoding='utf-8')
    except Exception:
        return
    
    new_content = content
    
    # 1. Environment Variables
    new_content = new_content.replace('MCPSHIELD_', 'MCP_PHALANX_')
    
    # 2. Display Names
    new_content = new_content.replace('MCPShield', 'MCP-Phalanx')
    new_content = new_content.replace('MCPshield', 'MCP-Phalanx')
    new_content = new_content.replace('MCP Shield', 'MCP-Phalanx')
    new_content = new_content.replace('MCP Sheild', 'MCP-Phalanx')
    new_content = new_content.replace('mcp shield', 'MCP-Phalanx')
    new_content = new_content.replace('mcp sheild', 'MCP-Phalanx')
    
    # 3. CLI Commands and Project Name
    new_content = new_content.replace('mcpshield-', 'mcp-phalanx-')
    new_content = new_content.replace('name = "mcpshield"', 'name = "mcp-phalanx"')
    
    # 4. Python module paths & imports
    new_content = new_content.replace('src/mcpshield', 'src/mcp_phalanx')
    new_content = new_content.replace('from mcpshield', 'from mcp_phalanx')
    new_content = new_content.replace('import mcpshield', 'import mcp_phalanx')
    new_content = new_content.replace('mcpshield.', 'mcp_phalanx.')
    new_content = new_content.replace('mcpshield/', 'mcp_phalanx/')
    
    # 5. Fallback for remaining lowercase
    new_content = new_content.replace('mcpshield', 'mcp_phalanx')
    
    if new_content != content:
        filepath.write_text(new_content, encoding='utf-8')
        print(f"Updated {filepath}")

def main():
    root = Path(r"D:\proj\mcp-middleware")
    exclude_dirs = {'.venv', '.git', '__pycache__', '.pytest_cache', '.ruff_cache', 'tmp', 'scratch', 'node_modules'}
    
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for f in filenames:
            process_file(Path(dirpath) / f)

if __name__ == "__main__":
    main()
