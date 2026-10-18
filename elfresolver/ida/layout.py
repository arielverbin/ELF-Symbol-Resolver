from __future__ import annotations
from enum import Enum, auto
from typing import Iterator
import ida_segment # type: ignore

_PLT = (".plt", ".plt.sec", ".plt.got", ".iplt")
_GOT = (".got", ".got.plt")
_VARIABLES = (".data", ".bss", ".rodata", ".sdata", ".sbss", ".tdata", ".tbss")  # name prefixes: .data.rel.ro too


class Region(Enum):
    """Where in the binary an address lies, by the segment IDA made of its ELF section."""

    OWN_CODE = auto()   # the binary's own code: an executable segment, other than the PLT
    PLT = auto()        # the PLT stubs of imported functions
    EXTERN = auto()     # IDA's extern segment, where it puts the imports
    GOT = auto()        # the GOT, whose slots hold the addresses code loads
    VARIABLES = auto()  # where global variables and string literals live
    OTHER = auto()      # anywhere else, or outside every segment

    @classmethod
    def of(cls, address: int) -> Region:
        segment = ida_segment.getseg(address)
        if segment is None:
            return cls.OTHER
        name = ida_segment.get_segm_name(segment)
        if name in _PLT:
            return cls.PLT
        if name in _GOT:
            return cls.GOT
        if name.startswith(_VARIABLES):
            return cls.VARIABLES
        if segment.type == ida_segment.SEG_XTRN:
            return cls.EXTERN
        return cls.OWN_CODE if segment.type == ida_segment.SEG_CODE else cls.OTHER

    def segments(self) -> Iterator[ida_segment.segment_t]:
        """Every segment in this region."""
        for index in range(ida_segment.get_segm_qty()):
            segment = ida_segment.getnseg(index)
            if Region.of(segment.start_ea) is self:
                yield segment
