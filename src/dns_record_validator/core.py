import ipaddress
import re


# RFC 1035 hostname: letters, digits, hyphens; labels 1-63 octets;
# a leading digit is permitted by RFC 1123 §2.1 (relaxed).
_LABEL = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)$")


class RecordError(ValueError):
    """Raised when a record's fields are syntactically or semantically invalid."""


class Record:
    """Base resource record.

    Each concrete subclass parses a *single* record. The shared parse()
    dispatches by a type tag, so callers can validate an A or an MX through
    one entry point without knowing the class up-front.
    """

    type = ""
    _fields = ()

    def __init__(self, **kwargs):
        missing = [n for n in self._fields if n not in kwargs]
        if missing:
            raise RecordError(
                f"{self.type}: missing required field(s): {', '.join(missing)}"
            )
        extras = set(kwargs) - set(self._fields)
        if extras:
            raise RecordError(
                f"{self.type}: unexpected field(s): {', '.join(sorted(extras))}"
            )
        for name, value in kwargs.items():
            setattr(self, name, value)

    def as_dict(self):
        return {"type": self.type, **{n: getattr(self, n) for n in self._fields}}

    def __eq__(self, other):
        return isinstance(other, type(self)) and self.as_dict() == other.as_dict()

    def __repr__(self):
        pairs = ", ".join(f"{n}={getattr(self, n)!r}" for n in self._fields)
        return f"{type(self).__name__}({pairs})"


class A(Record):
    """IPv4 address record (RFC 1035)."""

    type = "A"
    _fields = ("name", "address")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not _is_hostname(self.name):
            raise RecordError(f"A: invalid owner name: {self.name!r}")
        try:
            ipaddress.IPv4Address(self.address)
        except ValueError as exc:
            raise RecordError(f"A: invalid IPv4 address: {self.address!r}") from exc


class AAAA(Record):
    """IPv6 address record (RFC 3596)."""

    type = "AAAA"
    _fields = ("name", "address")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not _is_hostname(self.name):
            raise RecordError(f"AAAA: invalid owner name: {self.name!r}")
        try:
            ipaddress.IPv6Address(self.address)
        except ValueError as exc:
            raise RecordError(
                f"AAAA: invalid IPv6 address: {self.address!r}"
            ) from exc


class MX(Record):
    """Mail exchange record (RFC 1035)."""

    type = "MX"
    _fields = ("name", "preference", "exchange")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not _is_hostname(self.name):
            raise RecordError(f"MX: invalid owner name: {self.name!r}")
        if not isinstance(self.preference, int) or isinstance(self.preference, bool):
            raise RecordError(
                f"MX: preference must be int, got {type(self.preference).__name__}"
            )
        if not 0 <= self.preference <= 65535:
            raise RecordError(
                f"MX: preference out of range: {self.preference}"
            )
        if not _is_hostname(self.exchange):
            raise RecordError(f"MX: invalid exchange: {self.exchange!r}")


class TXT(Record):
    """Text record (RFC 1035).

    We accept a Python str as input. The 255-octet wire limit is checked
    against UTF-8 so the value can round-trip through DNS presentation format.
    """

    type = "TXT"
    _fields = ("name", "data")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not _is_hostname(self.name):
            raise RecordError(f"TXT: invalid owner name: {self.name!r}")
        if not isinstance(self.data, str):
            raise RecordError(
                f"TXT: data must be str, got {type(self.data).__name__}"
            )
        try:
            encoded = self.data.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise RecordError(f"TXT: data not UTF-8 encodable: {exc}") from exc
        if len(encoded) > 65535:
            raise RecordError(
                f"TXT: data too long ({len(encoded)} > 65535 bytes)"
            )


class SRV(Record):
    """Service record (RFC 2782).

    RFC 2782 constrains the owner name to _service._proto.name. We validate
    that shape strictly rather than accepting any hostname, because a
    correctly-shaped owner is what makes an SRV record useful.
    """

    type = "SRV"
    _fields = ("name", "priority", "weight", "port", "target")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not _is_srv_owner(self.name):
            raise RecordError(
                f"SRV: owner must be _service._proto.name: {self.name!r}"
            )
        for field in ("priority", "weight", "port"):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool):
                raise RecordError(
                    f"SRV: {field} must be int, got {type(value).__name__}"
                )
            if not 0 <= value <= 65535:
                raise RecordError(
                    f"SRV: {field} out of range: {value}"
                )
        if not _is_hostname(self.target):
            raise RecordError(f"SRV: invalid target: {self.target!r}")


class CNAME(Record):
    """Canonical name record (RFC 1035)."""

    type = "CNAME"
    _fields = ("name", "target")

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not _is_hostname(self.name):
            raise RecordError(f"CNAME: invalid owner name: {self.name!r}")
        if not _is_hostname(self.target):
            raise RecordError(f"CNAME: invalid target: {self.target!r}")


class SOA(Record):
    """Start of authority record (RFC 1035)."""

    type = "SOA"
    _fields = (
        "name", "mname", "rname", "serial", "refresh", "retry",
        "expire", "minimum",
    )

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        if not _is_hostname(self.name):
            raise RecordError(f"SOA: invalid owner name: {self.name!r}")
        if not _is_hostname(self.mname):
            raise RecordError(f"SOA: invalid mname: {self.mname!r}")
        if not _is_rname(self.rname):
            raise RecordError(
                f"SOA: rname must be an email-like domain name: {self.rname!r}"
            )
        for field in (
            "serial", "refresh", "retry", "expire", "minimum"
        ):
            value = getattr(self, field)
            if not isinstance(value, int) or isinstance(value, bool):
                raise RecordError(
                    f"SOA: {field} must be int, got {type(value).__name__}"
                )
            if not 0 <= value <= 0xFFFFFFFF:
                raise RecordError(
                    f"SOA: {field} out of 32-bit range: {value}"
                )


def validate(type_, **fields):
    """Validate a single resource record by type tag.

    Returns the parsed Record on success and raises RecordError on any
    failure. Example:

        >>> validate("A", name="www", address="192.0.2.1")
        A(name='www', address='192.0.2.1')
    """
    classes = {"A": A, "AAAA": AAAA, "MX": MX, "TXT": TXT,
              "SRV": SRV, "CNAME": CNAME, "SOA": SOA}
    cls = classes.get(type_)
    if cls is None:
        raise RecordError(f"unknown record type: {type_!r}")
    return cls(**fields)


def _is_hostname(name):
    """Owner/target name validator.

    Accepts "." (root) and a single trailing dot. Each label must be 1-63
    octets, consist of ASCII letters/digits/hyphens, not start or end with a
    hyphen, and not be all-numeric. An all-numeric final label would collide
    with an IP literal on the wire, so we reject it here even though some
    resolvers tolerate it.
    """
    if not isinstance(name, str) or not name:
        return False
    if name == ".":
        return True
    if name.endswith("."):
        name = name[:-1]
    if not name:
        return False
    labels = name.split(".")
    if len(labels) > 127:
        return False
    for label in labels:
        if not label:
            return False
        if not _LABEL.match(label):
            return False
        if label.isdigit():
            return False
    return True


def _is_srv_owner(name):
    """SRV owner: _service._proto.name[.]."""
    if not isinstance(name, str) or not name:
        return False
    if name.endswith("."):
        name = name[:-1]
    if name.count(".") < 2:
        return False
    first, second, rest = name.split(".", 2)
    if not (first.startswith("_") and _is_label(first[1:])):
        return False
    if not (second.startswith("_") and _is_label(second[1:])):
        return False
    if second[1:] not in ("tcp", "udp", "sctp", "dccp"):
        return False
    return _is_hostname(rest or ".")


def _is_label(value):
    """A non-empty label without leading/trailing hyphen."""
    return bool(value) and bool(_LABEL.match(value))


def _is_rname(value):
    """SOA rname: <local>.<domain>. with a non-empty local part.

    The local part is a single label (no embedded dots) per RFC 1035 §3.3.13,
    where the first unescaped dot in the wire form separates the mailbox
    name from the domain. We don't accept backslash escapes.
    """
    if not isinstance(value, str) or not value:
        return False
    if value.endswith("."):
        value = value[:-1]
    if not value:
        return False
    parts = value.split(".")
    if len(parts) < 2:
        return False
    if not parts[0]:
        return False
    if not _LABEL.match(parts[0]):
        return False
    return _is_hostname(".".join(parts[1:]) or ".")
