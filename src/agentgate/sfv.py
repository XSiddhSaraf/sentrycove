"""Minimal RFC 8941 Structured Field Values parser/serializer.

Only what RFC 9421 (HTTP Message Signatures) needs: Dictionaries whose
members are Items or Inner Lists, with Parameters. Strict by design:
malformed input raises ``SFVError`` rather than being guessed at.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Union

__all__ = [
    "SFVError",
    "Token",
    "Item",
    "InnerList",
    "BareItem",
    "parse_dictionary",
    "serialize_inner_list",
    "serialize_item",
]


class SFVError(ValueError):
    """Raised when a structured field cannot be parsed."""


class Token(str):
    """A structured-field Token (distinct from a quoted String)."""


BareItem = Union[int, Decimal, str, Token, bytes, bool]
Params = dict[str, BareItem]


@dataclass(frozen=True)
class Item:
    value: BareItem
    params: Params = field(default_factory=dict)


@dataclass(frozen=True)
class InnerList:
    items: tuple[Item, ...]
    params: Params = field(default_factory=dict)


_KEY_RE = re.compile(r"[a-z*][a-z0-9_\-.*]*")
_TOKEN_RE = re.compile(r"[A-Za-z*][!#$%&'*+\-.^_`|~0-9A-Za-z:/]*")
_NUMBER_RE = re.compile(r"-?[0-9]+(\.[0-9]+)?")
_B64_RE = re.compile(r"[A-Za-z0-9+/=]*")


class _Parser:
    def __init__(self, text: str) -> None:
        try:
            text.encode("ascii")
        except UnicodeEncodeError as exc:
            raise SFVError("structured fields must be ASCII") from exc
        self.s = text
        self.i = 0

    # -- helpers -------------------------------------------------------
    def _peek(self) -> str:
        return self.s[self.i] if self.i < len(self.s) else ""

    def _eof(self) -> bool:
        return self.i >= len(self.s)

    def _skip_sp(self) -> None:
        while self._peek() == " ":
            self.i += 1

    def _skip_ows(self) -> None:
        while self._peek() in (" ", "\t") and self._peek() != "":
            self.i += 1

    # -- grammar -------------------------------------------------------
    def parse_key(self) -> str:
        m = _KEY_RE.match(self.s, self.i)
        if not m:
            raise SFVError(f"invalid key at position {self.i}")
        self.i = m.end()
        return m.group(0)

    def parse_bare_item(self) -> BareItem:
        c = self._peek()
        if c == "-" or c.isdigit():
            return self._parse_number()
        if c == '"':
            return self._parse_string()
        if c == ":":
            return self._parse_bytes()
        if c == "?":
            return self._parse_boolean()
        if c.isalpha() or c == "*":
            return self._parse_token()
        raise SFVError(f"unexpected character {c!r} at position {self.i}")

    def _parse_number(self) -> Union[int, Decimal]:
        m = _NUMBER_RE.match(self.s, self.i)
        if not m:
            raise SFVError("invalid number")
        text = m.group(0)
        self.i = m.end()
        if m.group(1) is None:
            if len(text.lstrip("-")) > 15:
                raise SFVError("integer too long")
            return int(text)
        integer_part, frac = text.lstrip("-").split(".")
        if len(integer_part) > 12 or len(frac) > 3:
            raise SFVError("decimal out of range")
        return Decimal(text)

    def _parse_string(self) -> str:
        self.i += 1  # opening quote
        out: list[str] = []
        while True:
            if self._eof():
                raise SFVError("unterminated string")
            c = self.s[self.i]
            self.i += 1
            if c == "\\":
                if self._eof():
                    raise SFVError("dangling escape")
                nxt = self.s[self.i]
                self.i += 1
                if nxt not in ('"', "\\"):
                    raise SFVError("invalid escape")
                out.append(nxt)
            elif c == '"':
                return "".join(out)
            elif ord(c) < 0x20 or ord(c) > 0x7E:
                raise SFVError("invalid character in string")
            else:
                out.append(c)

    def _parse_token(self) -> Token:
        m = _TOKEN_RE.match(self.s, self.i)
        if not m:
            raise SFVError("invalid token")
        self.i = m.end()
        return Token(m.group(0))

    def _parse_bytes(self) -> bytes:
        self.i += 1
        end = self.s.find(":", self.i)
        if end == -1:
            raise SFVError("unterminated byte sequence")
        data = self.s[self.i : end]
        if not _B64_RE.fullmatch(data):
            raise SFVError("invalid base64 in byte sequence")
        self.i = end + 1
        try:
            padded = data + "=" * (-len(data) % 4)
            return base64.b64decode(padded, validate=True)
        except ValueError as exc:
            raise SFVError("invalid base64 in byte sequence") from exc

    def _parse_boolean(self) -> bool:
        self.i += 1
        c = self._peek()
        if c not in ("0", "1"):
            raise SFVError("invalid boolean")
        self.i += 1
        return c == "1"

    def parse_params(self) -> Params:
        params: Params = {}
        while self._peek() == ";":
            self.i += 1
            self._skip_sp()
            key = self.parse_key()
            value: BareItem = True
            if self._peek() == "=":
                self.i += 1
                value = self.parse_bare_item()
            params[key] = value
        return params

    def parse_item(self) -> Item:
        value = self.parse_bare_item()
        return Item(value, self.parse_params())

    def parse_inner_list(self) -> InnerList:
        if self._peek() != "(":
            raise SFVError("expected inner list")
        self.i += 1
        items: list[Item] = []
        while not self._eof():
            self._skip_sp()
            if self._peek() == ")":
                self.i += 1
                return InnerList(tuple(items), self.parse_params())
            items.append(self.parse_item())
            if self._peek() not in (" ", ")"):
                raise SFVError("inner list items must be space separated")
        raise SFVError("unterminated inner list")

    def parse_dictionary(self) -> dict[str, Union[Item, InnerList]]:
        result: dict[str, Union[Item, InnerList]] = {}
        self._skip_sp()
        if self._eof():
            return result
        while True:
            key = self.parse_key()
            if self._peek() == "=":
                self.i += 1
                if self._peek() == "(":
                    member: Union[Item, InnerList] = self.parse_inner_list()
                else:
                    member = self.parse_item()
            else:
                member = Item(True, self.parse_params())
            result[key] = member
            self._skip_ows()
            if self._eof():
                return result
            if self._peek() != ",":
                raise SFVError(f"expected ',' at position {self.i}")
            self.i += 1
            self._skip_ows()
            if self._eof():
                raise SFVError("trailing comma in dictionary")


def parse_dictionary(text: str) -> dict[str, Union[Item, InnerList]]:
    """Parse an RFC 8941 Dictionary field value."""
    return _Parser(text.strip(" ")).parse_dictionary()


# -- serialization -----------------------------------------------------


def _serialize_bare_item(value: BareItem) -> str:
    # bool must be checked before int: bool is a subclass of int.
    if isinstance(value, bool):
        return "?1" if value else "?0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, Decimal):
        q = value.quantize(Decimal("0.001"))
        text = format(q, "f").rstrip("0")
        return text + "0" if text.endswith(".") else text
    if isinstance(value, bytes):
        return ":" + base64.b64encode(value).decode("ascii") + ":"
    if isinstance(value, Token):
        return str(value)
    if isinstance(value, str):
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    raise SFVError(f"cannot serialize {type(value).__name__}")


def _serialize_params(params: Params) -> str:
    out = []
    for key, value in params.items():
        if value is True:
            out.append(f";{key}")
        else:
            out.append(f";{key}={_serialize_bare_item(value)}")
    return "".join(out)


def serialize_item(item: Item) -> str:
    return _serialize_bare_item(item.value) + _serialize_params(item.params)


def serialize_inner_list(inner: InnerList) -> str:
    body = " ".join(serialize_item(i) for i in inner.items)
    return f"({body}){_serialize_params(inner.params)}"
