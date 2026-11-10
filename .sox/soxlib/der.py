"""Minimal DER reader for the fields the verifier needs from a Fulcio leaf certificate.

Stdlib only, so the verifier runs from a bare clone on any machine. It does not validate the
certificate chain or signature (gh / sigstore does that); it extracts extension values so the
signer identity is checked independently of the tool that checked the signature.
"""


class DERError(ValueError):
    pass


def _read_tlv(buf, pos):
    if pos + 2 > len(buf):
        raise DERError("truncated TLV header")
    tag = buf[pos]
    length = buf[pos + 1]
    pos += 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4 or pos + n > len(buf):
            raise DERError("bad length")
        length = int.from_bytes(buf[pos:pos + n], "big")
        pos += n
    end = pos + length
    if end > len(buf):
        raise DERError("truncated value")
    return tag, buf[pos:end], end


def _children(value):
    out, pos = [], 0
    while pos < len(value):
        tag, v, pos = _read_tlv(value, pos)
        out.append((tag, v))
    return out


def decode_oid(value):
    if not value:
        raise DERError("empty OID")
    first = value[0]
    parts = [first // 40 if first < 80 else 2, first % 40 if first < 80 else first - 80]
    n = 0
    for b in value[1:]:
        n = (n << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(n)
            n = 0
    return ".".join(str(p) for p in parts)


def certificate_extensions(der):
    """Return {oid: raw extnValue bytes} for an X.509 certificate in DER form."""
    tag, cert, _ = _read_tlv(der, 0)
    if tag != 0x30:
        raise DERError("certificate is not a SEQUENCE")
    parts = _children(cert)
    if not parts or parts[0][0] != 0x30:
        raise DERError("no tbsCertificate")
    exts = {}
    for t, v in _children(parts[0][1]):
        if t != 0xA3:  # [3] EXPLICIT extensions
            continue
        seq = _children(v)
        if len(seq) != 1 or seq[0][0] != 0x30:
            raise DERError("bad extensions wrapper")
        for et, ev in _children(seq[0][1]):
            if et != 0x30:
                raise DERError("bad extension")
            fields = _children(ev)
            if not fields or fields[0][0] != 0x06:
                raise DERError("extension without OID")
            oid = decode_oid(fields[0][1])
            octets = [f for f in fields[1:] if f[0] == 0x04]
            if len(octets) != 1:
                raise DERError(f"extension {oid} without a single OCTET STRING")
            if oid in exts:
                raise DERError(f"duplicate extension {oid}")
            exts[oid] = octets[0][1]
    return exts


def fulcio_string(raw, oid):
    """Fulcio v2 extensions (1.3.6.1.4.1.57264.1.8+) are DER UTF8String; legacy ones are raw."""
    legacy = oid.rsplit(".", 1)[-1] in {"1", "2", "3", "4", "5", "6"}
    if legacy:
        return raw.decode("utf-8")
    tag, v, end = _read_tlv(raw, 0)
    if tag != 0x0C or end != len(raw):
        raise DERError(f"extension {oid} is not a single UTF8String")
    return v.decode("utf-8")


def san_uris(raw):
    """URIs ([6] IA5String) from a SubjectAltName extension value."""
    tag, v, _ = _read_tlv(raw, 0)
    if tag != 0x30:
        raise DERError("SAN is not a SEQUENCE")
    return [x.decode("ascii") for t, x in _children(v) if t == 0x86]
