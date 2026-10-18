from __future__ import annotations
import json
from dataclasses import fields
from typing import Any, ClassVar, Mapping, Self


class Serializable:
    """A value that can travel between the resolver and IDA.
    A dataclass is written as its fields; any other class says what it is written as."""

    _classes: ClassVar[dict[str, type[Serializable]]] = {}

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if cls.__name__ in Serializable._classes:
            raise TypeError(f"Another Serializable class is named {cls.__name__}: the JSON couldn't tell them apart")
        Serializable._classes[cls.__name__] = cls

    def serialize(self) -> bytes:
        return json.dumps(_written(self)).encode()

    @classmethod
    def from_serialized(cls, data: str | bytes) -> Self:
        """The value `data` is the serialization of. Raises ValueError if that isn't a `cls`."""
        value = _read(json.loads(data))
        if not isinstance(value, cls):
            raise ValueError(f"Not a {cls.__name__}: {value!r}")
        return value

    def to_fields(self) -> Mapping[str, object]:
        """What this value is written as: its dataclass fields."""
        return {field.name: getattr(self, field.name) for field in fields(self)}  # type: ignore[arg-type]

    @classmethod
    def from_fields(cls, values: Mapping[str, object]) -> Self:
        """The value written as `values` (see to_fields)."""
        return cls(**values)


def _written(value: object) -> object:
    match value:
        case Serializable():
            return {"type": type(value).__name__, **{name: _written(item) for name, item in value.to_fields().items()}}
        case tuple() | list():
            return [_written(item) for item in value]
        case _:
            return value


def _read(value: object) -> object:
    match value:
        case {"type": str(name), **values}:
            if (cls := Serializable._classes.get(name)) is None:
                raise ValueError(f"Nothing serializable is named {name!r}")
            return cls.from_fields({key: _read(item) for key, item in values.items()})
        case list():
            return tuple(_read(item) for item in value)
        case _:
            return value
