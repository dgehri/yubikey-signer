//! Tests for signed attributes canonical ordering.

use yubikey_signer::domain::pkcs7::{SignedAttributeLogical, SignedAttributesCanonical};
// public exports expected

#[test]
fn canonical_ordering_is_lexicographic_by_der() {
    // Three fake attributes with varying DER prefixes to test ordering.
    let a = SignedAttributeLogical {
        oid: "b".into(),
        der: vec![0x30, 0x03, 0x02, 0x01, 0x02],
    }; // ...02
    let b = SignedAttributeLogical {
        oid: "a".into(),
        der: vec![0x30, 0x03, 0x02, 0x01, 0x01],
    }; // ...01
    let c = SignedAttributeLogical {
        oid: "c".into(),
        der: vec![0x30, 0x03, 0x02, 0x01, 0x03],
    }; // ...03
    let canonical = SignedAttributesCanonical::new(vec![a.clone(), b.clone(), c.clone()]);
    let ordered_oids: Vec<_> = canonical.ordered().iter().map(|x| x.oid.as_str()).collect();
    // Expect order by DER bytes -> b(01), a(02), c(03) based on last byte
    assert_eq!(
        ordered_oids,
        vec!["a", "b", "c"],
        "Attributes not ordered lexicographically by DER"
    );
    // Determinism check: re-run should produce identical concatenation
    let canonical2 = SignedAttributesCanonical::new(vec![b, a, c]);
    assert_eq!(canonical.concatenated_der(), canonical2.concatenated_der());
}
