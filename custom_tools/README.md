# malhaus custom_tools

Drop Python files here, e.g. custom_tools/my_tools.py

A tool is any function with `is_tool = True`.
The easiest way is to use the existing decorator:

```python
from tools.cli_tools import tool

@tool
def my_tool(path: str) -> dict:
    """One sentence about what it does and when to use it."""
    return {"ok": True}

cat > custom_tools/README.md <<'MD'
# malhaus custom_tools

Drop Python files here, e.g. custom_tools/my_tools.py

A tool is any function with `is_tool = True`.
The easiest way is to use the existing decorator:

