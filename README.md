# dns-record-validator

Validates the syntax and field values of A, AAAA, MX, TXT, SRV, CNAME, and SOA
DNS resource records. Each record is a small class that raises `RecordError`
on any invalid field; `validate(type, **fields)` dispatches by type tag.

```python
from dns_record_validator import validate, RecordError

try:
    rec = validate("A", name="www", address="192.0.2.1")
    print(rec.as_dict())
except RecordError as exc:
    print("invalid:", exc)
```

## Why this exists

Zone files and provisioning APIs routinely accept records that are syntactically
legal but semantically broken: an MX whose exchange is a bare number, an AAAA
with an IPv4 literal, an SOA whose rname has no mailbox label, an SRV whose
owner is not `_service._proto.name`. This library catches that class of mistake
at ingestion time, before it reaches a nameserver.

The trade-off: we validate field *values*, not zone-level invariants. We do not
detect CNAME-at-apex collisions, mixed-case duplication, or forward/reverse
mismatches. Those need a full zone view; this library deliberately doesn't.

## Edges you will hit

- Owner and target names may carry a single trailing dot (FQDN form). Root is
  represented by the literal string `"."`.
- An all-numeric final label in a hostname is rejected, because it would collide
  with an IP literal on the wire. A leading digit (RFC 1123 relaxation) is fine.
- SRV owners are matched against `_service._proto.name` strictly; `_proto` is
  limited to `tcp`, `udp`, `sctp`, `dccp`.
- SOA `rname` is a single mailbox label followed by a domain — backslash
  escapes for dots inside the local part are not supported.
- TXT `data` is a Python `str`, validated against the 65535-octet wire limit
  using its UTF-8 length.

Exported names: `RecordError`, `Record`, `A`, `AAAA`, `MX`, `TXT`, `SRV`,
`CNAME`, `SOA`, `validate`.
