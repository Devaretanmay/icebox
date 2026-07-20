"""ICEBOX recipe: protect an OpenAI Agents SDK agent.

Starting point, not a maintained integration. The pattern: before the agent
runs a tool, ask ICEBOX. Only proceed when allowed.

    from icebox import govern
    from openai_agents import Tool

    def guarded(run_tool):
        def wrapper(tool: Tool, args):
            if govern(tool.name, target=args.get("target", "unknown")):
                return run_tool(tool, args)
            return None
        return wrapper
"""

from icebox import govern


def protect(tool_runner):
    """Wrap the OpenAI Agents tool runner so every tool call is governed."""
    def wrapper(tool, args=None):
        args = args or {}
        target = args.get("target") or "unknown"
        if govern(tool.name, target=target):
            return tool_runner(tool, args)
        return None
    return wrapper
