"""Three-valued rule evaluation: missing metrics stay unknown, even under NOT."""

from vulnrelay.schemas import Condition, Group


def evaluate(node: Condition | Group, context: dict) -> dict:
    if isinstance(node, Group):
        children = [evaluate(child, context) for child in node.children]
        values = [child["result"] for child in children]
        if node.kind == "all":
            value = False if False in values else None if None in values else True
        elif node.kind == "any":
            value = True if True in values else None if None in values else False
        else:
            value = None if values[0] is None else not values[0]
        return {"kind": node.kind, "result": value, "children": children}
    actual = context.get(node.field)
    if actual is None:
        result = None
    elif node.op == "gte":
        result = actual >= node.value
    elif node.op == "lte":
        result = actual <= node.value
    elif node.op == "eq":
        result = (
            actual.casefold() == node.value.casefold()
            if isinstance(actual, str)
            else actual == node.value
        )
    elif node.op == "in":
        result = str(actual).casefold() in [value.casefold() for value in node.value]
    elif isinstance(actual, list):
        result = node.value.casefold() in [str(value).casefold() for value in actual]
    else:
        result = node.value.casefold() in str(actual).casefold()
    return {
        "kind": "condition",
        "field": node.field,
        "op": node.op,
        "expected": node.value,
        "actual": actual,
        "result": result,
    }
