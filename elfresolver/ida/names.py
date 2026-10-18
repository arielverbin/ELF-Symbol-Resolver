from __future__ import annotations
import ctypes
import ctypes.util
import functools
import re
from typing import Callable

_ABI_TAG = re.compile(r"\[abi:[^\]]*\]")
_CLOSURE = re.compile(r"'(lambda|unnamed)(\d*)'")       # LLVM's names of a lambda's, and an unnamed type's
_CLONE = re.compile(r" \((\.[\w.]+)\)")                  # LLVM's ' (.cold)'
_ADJACENT_CLOSES = re.compile(r"(?<!operator)>(?=>)")    # LLVM's '>>', in a template argument list


def name_forms(name: str, demangled: str | None) -> tuple[str, ...]:
    """
    Every form of a symbol's name it answers to: as linked; demangled, as GNU's
    tools show it (see demangled); and that without its parameter list, without
    the return type a function template's instance has first, and without ABI tags.

        'int ns::f<int>(int)' -> 'ns::f<int>(int)', 'int ns::f<int>', 'ns::f<int>'
    """
    forms = [name]
    if demangled is not None:
        for full in dict.fromkeys([demangled, _ABI_TAG.sub("", demangled)]):
            named = without_return_type(full)
            forms += [full, named, without_parameters(full), without_parameters(named)]
    return tuple(dict.fromkeys(forms))


def demangled(name: str) -> str | None:
    """
    `name` demangled, as GNU's tools (c++filt, nm -C) show it; None if it isn't
    a mangled C++ name. It is demangled by the C++ runtime IDA itself runs on:
    libstdc++ demangles as c++filt does, libc++abi (LLVM's) nearly so, and its
    differences are written over (see gnu_style). None without either (Windows).
    """
    if not name.startswith("_Z") or (demangle := _cxa_demangle()) is None:
        return None
    text = demangle(name)
    return gnu_style(text) if text is not None else None


def gnu_style(text: str) -> str:
    """
    A name LLVM's demangler gave, as GNU's gives it; a name GNU's gave, as it was:
    `{lambda(int)#1}` for 'lambda'(int), `{unnamed type#1}` for 'unnamed',
    `> >` for >> closing two template argument lists, and `[clone .cold]` for (.cold).
    """
    pieces, start = [], 0
    while (closure := _CLOSURE.search(text, start)) is not None:
        number = int(closure[2]) + 2 if closure[2] else 1   # 'lambda' is #1, 'lambda0' #2, ...
        pieces.append(text[start:closure.start()])
        if closure[1] == "unnamed":
            pieces.append(f"{{unnamed type#{number}}}")
            start = closure.end()
            continue
        end = _closing_parenthesis(text, closure.end())
        pieces.append(f"{{lambda{text[closure.end():end + 1]}#{number}}}")
        start = end + 1
    text = "".join(pieces) + text[start:]
    return _CLONE.sub(r" [clone \1]", _ADJACENT_CLOSES.sub("> ", text))


def without_parameters(name: str) -> str:
    """A demangled name without its parameter list: 'ns::Box<int>::get(int) const' -> 'ns::Box<int>::get'."""
    depth = 0
    for index in range(name.rfind(")"), -1, -1):
        depth += {")": 1, "(": -1}.get(name[index], 0)
        if depth == 0:
            return name[:index]
    return name


def without_return_type(name: str) -> str:
    """
    A function template instance's demangled name without the return type GNU
    shows first: 'int ns::f<int>(int)' -> 'ns::f<int>(int)'. Another name is as it was.
    """
    head = without_parameters(name)
    if not head.endswith(">"):
        return name   # only a template instance has a return type in its name
    depth = 0
    for index in range(len(head) - 1, -1, -1):
        depth += {">": 1, ")": 1, "<": -1, "(": -1}.get(head[index], 0)
        if head[index] == " " and depth == 0 and not head[:index].endswith(("operator<<", "operator>>", "operator<", "operator>")):
            return name[index + 1:]
    return name


def _closing_parenthesis(text: str, opening: int) -> int:
    """The index of the parenthesis closing the one at `opening`."""
    depth = 0
    for index in range(opening, len(text)):
        depth += {"(": 1, ")": -1}.get(text[index], 0)
        if depth == 0:
            return index
    return len(text) - 1


@functools.cache
def _cxa_demangle() -> Callable[[str], str | None] | None:
    """The C++ runtime's demangler, __cxa_demangle, as a function of a name; None without a runtime that has one."""
    for library in (None, ctypes.util.find_library("stdc++"), ctypes.util.find_library("c++abi")):
        try:
            function = ctypes.CDLL(library).__cxa_demangle
            free = ctypes.CDLL(ctypes.util.find_library("c")).free
        except (OSError, AttributeError, TypeError):
            continue
        function.restype = ctypes.c_void_p
        function.argtypes = [ctypes.c_char_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
        free.argtypes = [ctypes.c_void_p]

        def demangle(name: str) -> str | None:
            status = ctypes.c_int()
            pointer = function(name.encode(), None, None, ctypes.byref(status))
            if status.value != 0 or not pointer:
                return None
            try:
                return ctypes.string_at(pointer).decode(errors="replace")
            finally:
                free(pointer)
        return demangle
    return None
