from __future__ import annotations
import logging
from typing import Callable
from elfresolver.exceptions import ResolveInterrupted
from elfresolver.ida.symbols import IDASymbol  # with every kind it registers (see IDASymbol.kinds)
from elfresolver.symbols import Symbol

logger = logging.getLogger(__name__)


class SymbolResolution:
    """Every symbol met in one database: an IDASymbol of its kind, built once, so it resolves once."""

    def __init__(self, interrupted: Callable[[], bool] = lambda: False) -> None:
        """`interrupted` is asked before every constraint is met: True stops the resolve under way."""
        self.interrupted = interrupted
        self._symbols: dict[Symbol, IDASymbol] = {}  # cache resolved symbols

    def resolve(self, symbol: Symbol) -> IDASymbol:
        """Resolves the IDASymbol of `symbol` (main logic entry.)"""
        resolvable = self.as_resolvable(symbol)
        if resolvable.resolved:
            logger.info("%r: %d match(es), resolved before", symbol, len(resolvable.resolve()))
        else:
            logger.info("Resolving %r", symbol)
            matches = resolvable.resolve()
            logger.info("%r: %d match(es)", symbol, len(matches))
        return resolvable

    def as_resolvable(self, symbol: Symbol) -> IDASymbol:
        """The IDASymbol of `symbol`: the same one for every symbol equal to it."""
        if symbol not in self._symbols:
            self._symbols[symbol] = IDASymbol.kinds[type(symbol)](symbol, self)
        else:
            logger.debug(f"symbol {symbol!r} already constructed")

        return self._symbols[symbol]

    def stop_if_cancelled(self) -> None:
        """Raise ResolveInterrupted if the resolver has cancelled the resolve under way (see `interrupted`)."""
        if self.interrupted():
            raise ResolveInterrupted("The resolver cancelled the resolve")
