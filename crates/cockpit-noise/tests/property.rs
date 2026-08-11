use cockpit_noise::{HandshakeFrame, RemoteNoisePrologueV1, RemoteNoiseRecordV1};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn remote_noise_parser_property_corpus_never_panics_or_overallocates(bytes in prop::collection::vec(any::<u8>(), 0..70_000)) {
        let _ = RemoteNoisePrologueV1::decode(&bytes);
        let _ = HandshakeFrame::decode(&bytes, 1);
        let parsed = RemoteNoiseRecordV1::decode_plaintext(&bytes, 0);
        if let Ok(record) = parsed {
            prop_assert!(record.payload.len() <= 65_505);
        }
    }
}
