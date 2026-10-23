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
        return json.dumps(self._to_json(self)).encode()

    @classmethod
    def from_serialized(cls, data: str | bytes) -> Self:
        """The value `data` is the serialization of. Raises ValueError if that isn't a `cls`."""
        value = Serializable._from_json(json.loads(data))
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

    @staticmethod
    def _to_json(value: object) -> object:
        """`value` as JSON holds it: a Serializable as its fields and its class's name, a sequence as a list."""
        match value:
            case Serializable():
                return {"type": type(value).__name__, **{name: Serializable._to_json(item) for name, item in value.to_fields().items()}}
            case tuple() | list():
                return [Serializable._to_json(item) for item in value]
            case _:
                return value

    @staticmethod
    def _from_json(value: object) -> object:
        """The value JSON holds as `value` (see _to_json): a list comes back a tuple, as values are immutable."""
        match value:
            case {"type": str(name), **values}:
                if (cls := Serializable._classes.get(name)) is None:
                    raise ValueError(f"Nothing serializable is named {name!r}")
                return cls.from_fields({key: Serializable._from_json(item) for key, item in values.items()})
            case list():
                return tuple(Serializable._from_json(item) for item in value)
            case _:
                return value
