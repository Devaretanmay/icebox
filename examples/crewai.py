"""ICEBOX recipe: protect a CrewAI agent.

Starting point, not a maintained integration. The pattern: govern every tool
before the crew executes it.

    from icebox import govern

    def guarded_tool(tool, args):
        if govern(tool.name, target=args.get("target", "unknown")):
            return tool.run(args)
        return None
"""

from icebox import govern


def protect(tool_runner):
    """Wrap a CrewAI tool runner so every tool call is governed."""
    def wrapper(tool, args=None):
        args = args or {}
        target = args.get("target") or "unknown"
        if govern(tool.name, target=target):
            return tool_runner(tool, args)
        return None
    return wrapper
