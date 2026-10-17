from __future__ import annotations


def name_forms(name: str, demangled: str | None) -> tuple[str, ...]:
    """Every form of a symbol's name it answers to: as linked, demangled, and demangled without its parameter list."""
    forms = [name] if demangled is None else [name, demangled, without_parameters(demangled)]
    return tuple(dict.fromkeys(forms))


def without_parameters(name: str) -> str:
    """A demangled name without its parameter list: 'ns::Box<int>::get(int) const' -> 'ns::Box<int>::get'."""
    depth = 0
    for index in range(name.rfind(")"), -1, -1):
        depth += {")": 1, "(": -1}.get(name[index], 0)
        if depth == 0:
            return name[:index]
    return name
