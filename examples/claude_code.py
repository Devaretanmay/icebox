"""ICEBOX recipe: protect a Claude Code agent.

This is a starting point, not a maintained integration. It shows the pattern:
intercept a tool call, ask ICEBOX, and only run it when allowed.

Wire this into your Claude Code setup however you run it — for example, wrap
the function your agent calls to execute a shell command or tool.

    from icebox import govern

    def guarded_tool(name, input):
        if govern(name, target=input.get("target", "unknown")):
            return real_tool(name, input)
        return None  # ICEBOX stopped it
"""

from icebox import govern


def protect(tool_fn):
    """Wrap a Claude Code tool function so ICEBOX governs every call.

    tool_fn is your real tool executor: tool_fn(name, input) -> result.
    """
    def wrapper(name, input=None):
        input = input or {}
        target = input.get("target") or input.get("command") or "unknown"
        if govern(name, target=target):
            return tool_fn(name, input)
        return None
    return wrapper
