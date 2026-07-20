"""ICEBOX recipe: stage an AutoGen group chat.

Starting point, not a maintained integration. The group runs its whole
workflow inside a Session and may iterate freely; reality only sees the first
success.

    from icebox import icebox

    with icebox(profile="development") as session:
        session.run(lambda: my_group_chat.run())
"""

from icebox import icebox


def stage(task: str, group_fn, *, profile: str | None = None):
    """Run ``group_fn`` inside an ICEBOX Session and return its audit."""
    with icebox(task=task, profile=profile) as session:
        return session.run(group_fn)
