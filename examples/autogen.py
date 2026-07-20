"""ICEBOX recipe: protect an AutoGen agent.

Starting point, not a maintained integration. The pattern: govern every tool
call before the agent executes it.

    from icebox import govern

    def guarded_tool(name, args):
        if govern(name, target=args.get("target", "unknown")):
            return real_tool(name, args)
        return None
"""

from icebox import govern


def protect(tool_runner):
    """Wrap an AutoGen tool runner so every tool call is governed."""
    def wrapper(name, args=None):
        args = args or {}
        target = args.get("target") or "unknown"
        if govern(name, target=target):
            return tool_runner(name, args)
        return None
    return wrapper
