"""OpenAI tool-calling schemas and LangChain integration for ICEBOX modules.

Zero hard dependencies — LangChain support is opt-in (import guarded).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from ._sdk import IceboxClient


def _options_to_properties(options_json: dict) -> tuple[dict, list[str]]:
    """Convert ICEBOX module options_json into JSON Schema properties + required list."""
    properties: dict[str, Any] = {}
    required: list[str] = []

    if not isinstance(options_json, dict):
        return properties, required

    for key, val in options_json.items():
        if isinstance(val, bool):
            prop: dict[str, Any] = {"type": "boolean", "description": key}
        elif isinstance(val, int):
            prop = {"type": "integer", "description": key}
            if val == 0:
                required.append(key)
        elif isinstance(val, float):
            prop = {"type": "number", "description": key}
        elif val is None or val == "":
            prop = {"type": "string", "description": key}
            required.append(key)
        else:
            prop = {"type": "string", "description": key}
        properties[key] = prop

    return properties, required


def openai_tools(client: IceboxClient) -> list[dict]:
    """Return OpenAI-compatible tool definitions for every ICEBOX module.

    Pass the result directly to ``openai.chat.completions.create(tools=...)``.
    """
    modules = client.list_modules()
    tools = []
    for mod in modules:
        name = mod["name"]
        try:
            detail = client.get_module(name)
            opts = detail.get("options") or {}
        except Exception:
            opts = {}

        properties, required = _options_to_properties(opts)
        properties["target"] = {
            "type": "string",
            "description": "Target IP address or hostname",
        }
        properties["sandbox"] = {
            "type": "boolean",
            "description": "Run inside an isolated Docker sandbox",
        }
        required_fields = ["target"] + [r for r in required if r != "host"]

        tools.append(
            {
                "type": "function",
                "function": {
                    "name": f"icebox_{name}",
                    "description": mod.get(
                        "description", f"Run ICEBOX module: {name}"
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": properties,
                        "required": required_fields,
                    },
                },
            }
        )
    return tools


def dispatch_tool_call(client: IceboxClient, tool_name: str, arguments: dict) -> dict:
    """Execute an OpenAI tool call returned by the model.

    ``tool_name`` must match a name returned by :func:`openai_tools`.
    """
    if not tool_name.startswith("icebox_"):
        raise ValueError(f"Not an ICEBOX tool: {tool_name}")
    module_name = tool_name[len("icebox_"):]
    target = arguments.pop("target", "")
    sandbox = arguments.pop("sandbox", False)
    return client.run_module(module_name, target=target, sandbox=sandbox, options=arguments)


try:
    from langchain.tools import BaseTool  # type: ignore[import]
    from pydantic import BaseModel, Field  # type: ignore[import]

    class _IceboxInput(BaseModel):
        target: str = Field(description="Target IP address or hostname")
        sandbox: bool = Field(default=False, description="Run in Docker sandbox")
        options: dict = Field(default_factory=dict, description="Module-specific options")

    class IceboxTool(BaseTool):
        """LangChain-compatible tool that wraps a single ICEBOX module."""

        name: str
        description: str
        client: Any
        module: str

        class Config:
            arbitrary_types_allowed = True

        args_schema: type[BaseModel] = _IceboxInput

        def _run(self, target: str, sandbox: bool = False, options: dict | None = None) -> str:
            result = self.client.run_module(
                self.module, target=target, sandbox=sandbox, options=options or {}
            )
            return str(result)

        async def _arun(self, target: str, sandbox: bool = False, options: dict | None = None) -> str:
            return self._run(target, sandbox, options)

except ImportError:
    class IceboxTool:  # type: ignore[no-redef]
        """Stub — install langchain to enable LangChain integration."""

        def __init__(self, *args, **kwargs):
            raise ImportError(
                "Install langchain to use IceboxTool: pip install 'icebox-sdk[langchain]'"
            )
