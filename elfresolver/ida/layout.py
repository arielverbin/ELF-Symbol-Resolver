from __future__ import annotations
from typing import Iterator
import ida_bytes # type: ignore
import ida_segment # type: ignore

_PLT = (".plt", ".plt.sec", ".plt.got", ".iplt")
_GOT = (".got", ".got.plt")
_VARIABLES = (".data", ".bss", ".rodata", ".sdata", ".sbss", ".tdata", ".tbss")  # name prefixes: .data.rel.ro too


def in_own_code(address: int) -> bool:
    """True inside the binary's own code: an executable segment, other than the PLT."""
    segment = ida_segment.getseg(address)
    return segment is not None and segment.type == ida_segment.SEG_CODE and not in_plt(address)


def in_plt(address: int) -> bool:
    return _segment_name(address) in _PLT


def in_variables(address: int) -> bool:
    """True inside a segment where global variables and string literals live."""
    return (_segment_name(address) or "").startswith(_VARIABLES)


def variable_segments() -> Iterator[ida_segment.segment_t]:
    """Every segment where global variables and string literals live."""
    for index in range(ida_segment.get_segm_qty()):
        segment = ida_segment.getnseg(index)
        if ida_segment.get_segm_name(segment).startswith(_VARIABLES):
            yield segment


def is_cell(address: int) -> bool:
    """True for a cell that only holds a pointer for code to load: a GOT slot, or a data word inside code (an ARM literal pool)."""
    return _segment_name(address) in _GOT or (in_own_code(address) and ida_bytes.is_data(ida_bytes.get_flags(address)))


def _segment_name(address: int) -> str | None:
    """The name of the segment `address` lies in: IDA names a segment after its ELF section."""
    segment = ida_segment.getseg(address)
    return ida_segment.get_segm_name(segment) if segment is not None else None
