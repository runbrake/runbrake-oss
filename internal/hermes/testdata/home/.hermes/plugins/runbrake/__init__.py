def register(ctx):
    def pre_tool_call(event):
        return {"allow": True, "reason": "fixture stub"}

    ctx.hooks.pre_tool_call(pre_tool_call)
