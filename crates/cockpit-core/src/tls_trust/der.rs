//! Minimal, bounds-checked DER walk that locates a certificate's
//! SubjectPublicKeyInfo. Only used to hash keys for the distrust list; the
//! certificate itself is still fully validated by the inner verifier.

const SEQUENCE: u8 = 0x30;
const INTEGER: u8 = 0x02;
const EXPLICIT_VERSION: u8 = 0xA0;

/// One DER TLV: its tag, its value, the full encoding, and what follows it.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    encoded: &'a [u8],
    rest: &'a [u8],
}

fn read_tlv(input: &[u8]) -> Option<Tlv<'_>> {
    let (&tag, after_tag) = input.split_first()?;
    // Multi-byte (high-tag-number) tags never appear in the fields we walk.
    if tag & 0x1F == 0x1F {
        return None;
    }
    let (&first, after_len) = after_tag.split_first()?;
    let (len, header_rest) = if first < 0x80 {
        (usize::from(first), after_len)
    } else {
        let count = usize::from(first & 0x7F);
        // DER forbids indefinite lengths; certificates never need > 4 bytes.
        if count == 0 || count > 4 || after_len.len() < count {
            return None;
        }
        let (len_bytes, rest) = after_len.split_at(count);
        if len_bytes[0] == 0 {
            return None;
        }
        let len = len_bytes
            .iter()
            .fold(0usize, |acc, &byte| (acc << 8) | usize::from(byte));
        if len < 0x80 {
            return None;
        }
        (len, rest)
    };
    if header_rest.len() < len {
        return None;
    }
    let header_len = input.len() - header_rest.len();
    let (value, rest) = header_rest.split_at(len);
    Some(Tlv {
        tag,
        value,
        encoded: &input[..header_len + len],
        rest,
    })
}

fn expect(input: &[u8], tag: u8) -> Option<Tlv<'_>> {
    read_tlv(input).filter(|tlv| tlv.tag == tag)
}

/// The full DER encoding (tag, length and value) of the certificate's
/// `subjectPublicKeyInfo`, i.e. the bytes whose SHA-256 is the SPKI hash.
pub(super) fn subject_public_key_info(cert_der: &[u8]) -> Option<&[u8]> {
    let certificate = expect(cert_der, SEQUENCE)?;
    let tbs = expect(certificate.value, SEQUENCE)?;
    let mut fields = tbs.value;
    if fields.first() == Some(&EXPLICIT_VERSION) {
        fields = read_tlv(fields)?.rest;
    }
    let serial = expect(fields, INTEGER)?;
    let signature = expect(serial.rest, SEQUENCE)?;
    let issuer = expect(signature.rest, SEQUENCE)?;
    let validity = expect(issuer.rest, SEQUENCE)?;
    let subject = expect(validity.rest, SEQUENCE)?;
    let spki = expect(subject.rest, SEQUENCE)?;
    Some(spki.encoded)
}
