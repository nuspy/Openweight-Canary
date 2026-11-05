"""A small reader of the Python the model writes in this task. It does not run the code: it walks the syntax tree and evaluates only a few forms
(strings, f-strings, dicts, lists, json.dumps and json.loads, print, len, open for reading and writing, simple string methods).
Anything else stops it, and what was printed until then is the answer, as if the script had stopped there.

Files go to the world that owns this reader (`world.read_file`, `world.write_file`)."""
from __future__ import annotations

import ast
import json
import textwrap

SAFE_MODULES = {"json", "re", "os", "sys", "textwrap", "datetime", "pathlib", "time", "csv", "io"}
STR_METHODS = {"strip", "lstrip", "rstrip", "replace", "split", "splitlines", "join", "lower", "upper", "startswith", "endswith", "format", "title"}


class Unsupported(Exception):
    pass


class _File:
    def __init__(self, world, path: str, mode: str):
        self.world, self.path, self.mode = world, path, mode
        if "w" in mode:
            world.write_file(path, "")

    def write(self, text):
        self.world.write_file(self.path, str(text), append=True)
        return len(str(text))

    def read(self):
        text = self.world.read_file(self.path)
        if text is None:
            raise FileNotFoundError(f"[Errno 2] No such file or directory: '{self.path}'")
        return text


class PyLite:
    def __init__(self, world):
        self.world, self.env, self.out = world, {}, []

    def run(self, code: str) -> str:
        try:
            tree = ast.parse(code)
        except SyntaxError as exc:
            return f"  File \"<string>\", line {exc.lineno}\nSyntaxError: {exc.msg}"
        try:
            self.block(tree.body)
        except Unsupported:
            pass                                    # the script stops here; what it printed stays
        except FileNotFoundError as exc:
            self.out.append(f"Traceback (most recent call last):\n  File \"<string>\", line 1, in <module>\nFileNotFoundError: {exc}")
        except (KeyError, IndexError, TypeError, ValueError, AttributeError) as exc:
            self.out.append(f"Traceback (most recent call last):\n  File \"<string>\", line 1, in <module>\n{type(exc).__name__}: {exc}")
        return "".join(self.out).rstrip("\n")

    # -- statements

    def block(self, body: list) -> None:
        for node in body:
            self.stmt(node)

    def stmt(self, node) -> None:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name.split(".")[0] for a in node.names] if isinstance(node, ast.Import) else [node.module.split(".")[0]]
            if any(n not in SAFE_MODULES for n in names):
                raise Unsupported(names)
            for a in (node.names if isinstance(node, ast.Import) else []):
                self.env[a.asname or a.name.split(".")[0]] = ("module", a.name.split(".")[0])
        elif isinstance(node, ast.Assign):
            value = self.ev(node.value)
            for target in node.targets:
                self.assign(target, value)
        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name) and isinstance(node.op, ast.Add):
            self.env[node.target.id] = self.env[node.target.id] + self.ev(node.value)
        elif isinstance(node, ast.Expr):
            self.ev(node.value)
        elif isinstance(node, ast.With):
            for item in node.items:
                value = self.ev(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, value)
            self.block(node.body)
        elif isinstance(node, ast.Try):
            self.block(node.body)
        elif isinstance(node, ast.If) and isinstance(node.test, ast.Constant):
            self.block(node.body if node.test.value else node.orelse)
        elif isinstance(node, (ast.Pass, ast.Global, ast.Nonlocal)):
            pass
        else:
            raise Unsupported(type(node).__name__)

    def assign(self, target, value) -> None:
        if isinstance(target, ast.Name):
            self.env[target.id] = value
        elif isinstance(target, ast.Subscript):
            self.ev(target.value)[self.ev(target.slice)] = value
        else:
            raise Unsupported("target")

    # -- expressions

    def ev(self, node):
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id]
            raise Unsupported(node.id)
        if isinstance(node, ast.JoinedStr):
            return "".join(str(self.ev(v.value)) if isinstance(v, ast.FormattedValue) else str(v.value) for v in node.values)
        if isinstance(node, ast.Dict):
            return {self.ev(k): self.ev(v) for k, v in zip(node.keys, node.values)}
        if isinstance(node, ast.List):
            return [self.ev(e) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self.ev(e) for e in node.elts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self.ev(node.left) + self.ev(node.right)
        if isinstance(node, ast.Subscript):
            return self.ev(node.value)[self.ev(node.slice)]
        if isinstance(node, ast.Slice):
            return slice(*(self.ev(p) if p is not None else None for p in (node.lower, node.upper, node.step)))
        if isinstance(node, ast.Call):
            return self.call(node)
        raise Unsupported(type(node).__name__)

    def call(self, node):
        args = [self.ev(a) for a in node.args]
        kwargs = {k.arg: self.ev(k.value) for k in node.keywords if k.arg}
        fn = node.func
        if isinstance(fn, ast.Name):
            if fn.id == "print":
                self.out.append(kwargs.get("sep", " ").join(str(a) for a in args) + kwargs.get("end", "\n"))
                return None
            if fn.id == "len":
                return len(args[0])
            if fn.id == "str":
                return str(args[0])
            if fn.id == "open":
                return _File(self.world, args[0], args[1] if len(args) > 1 else kwargs.get("mode", "r"))
            raise Unsupported(fn.id)
        if isinstance(fn, ast.Attribute):
            if isinstance(fn.value, ast.Name) and self.env.get(fn.value.id) == ("module", "json"):
                if fn.attr == "dumps":
                    return json.dumps(args[0], indent=kwargs.get("indent"), ensure_ascii=kwargs.get("ensure_ascii", True),
                                      sort_keys=kwargs.get("sort_keys", False))
                if fn.attr == "loads":
                    return json.loads(args[0])
                if fn.attr == "dump":
                    args[1].write(json.dumps(args[0], indent=kwargs.get("indent"), ensure_ascii=kwargs.get("ensure_ascii", True)))
                    return None
            if isinstance(fn.value, ast.Name) and self.env.get(fn.value.id) == ("module", "textwrap") and fn.attr == "dedent":
                return textwrap.dedent(args[0])
            target = self.ev(fn.value)
            if isinstance(target, _File) and fn.attr in ("write", "read"):
                return getattr(target, fn.attr)(*args)
            if isinstance(target, str) and fn.attr in STR_METHODS:
                return getattr(target, fn.attr)(*args, **kwargs)
        raise Unsupported("call")
