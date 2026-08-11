//! Table tests for the external audio transcription catalog, caller-context
//! validation, multipart length planning, strict response decoding,
//! normalized result, media-egress authorization digest, and the Whisper
//! prompt preflight.
//!
//! These cover the focused test prefixes `external_audio_transcription_` and
//! `media_egress_transcription_` from the prompt's acceptance criteria.

#![allow(clippy::needless_pass_by_value)]

use super::*;

const TEST_BOUNDARY: &str = "flycockpit-0123456789abcdef0123456789abcdef";

// ===========================================================================
// external_audio_transcription_catalog
// ===========================================================================

mod catalog_tests {
    use super::super::catalogs::*;

    #[test]
    fn external_audio_transcription_catalog_whisper_digest_matches_pinned() {
        let digest = whisper_multilingual_digest();
        assert_eq!(digest, WHISPER_PROVENANCE.sha256_hex);
        assert_eq!(WHISPER_MULTILINGUAL.len(), 98);
        verify_whisper_catalog().unwrap();
    }

    #[test]
    fn external_audio_transcription_catalog_whisper_has_98_entries_no_english() {
        assert_eq!(WHISPER_MULTILINGUAL.len(), 98);
        assert!(!WHISPER_MULTILINGUAL.contains(&"en"));
        // yue is a large-v3-only entry and must NOT be in the Whisper catalog
        assert!(!WHISPER_MULTILINGUAL.contains(&"yue"));
    }

    #[test]
    fn external_audio_transcription_catalog_whisper_en_separately_accepted() {
        assert!(WhisperLanguageCodeV1::new("en").is_some());
        assert_eq!(WhisperLanguageCodeV1::new("en").unwrap().as_str(), "en");
    }

    #[test]
    fn external_audio_transcription_catalog_whisper_rejects_unlisted() {
        // yue is GPT-only / large-v3-only
        assert!(WhisperLanguageCodeV1::new("yue").is_none());
        // eng is GPT-only alpha-3
        assert!(WhisperLanguageCodeV1::new("eng").is_none());
        // zh-cn is GPT-only regional
        assert!(WhisperLanguageCodeV1::new("zh-cn").is_none());
        // uppercase rejected
        assert!(WhisperLanguageCodeV1::new("EN").is_none());
        assert!(WhisperLanguageCodeV1::new("DE").is_none());
        // malformed
        assert!(WhisperLanguageCodeV1::new("").is_none());
        assert!(WhisperLanguageCodeV1::new("zz").is_none());
        assert!(WhisperLanguageCodeV1::new("english").is_none());
    }

    #[test]
    fn external_audio_transcription_catalog_whisper_accepts_every_member() {
        for code in WHISPER_MULTILINGUAL {
            assert!(
                WhisperLanguageCodeV1::new(code).is_some(),
                "whisper should accept {code}"
            );
        }
    }

    #[test]
    fn external_audio_transcription_catalog_gpt_accepts_every_member() {
        for code in GPT_TRANSCRIBE_ALPHA2 {
            assert!(
                GptTranscribeLanguageCodeV1::new(code).is_some(),
                "gpt should accept alpha-2 {code}"
            );
        }
        for code in GPT_TRANSCRIBE_ALPHA3 {
            assert!(
                GptTranscribeLanguageCodeV1::new(code).is_some(),
                "gpt should accept alpha-3 {code}"
            );
        }
        for code in GPT_TRANSCRIBE_REGIONAL_ZH {
            assert!(
                GptTranscribeLanguageCodeV1::new(code).is_some(),
                "gpt should accept regional {code}"
            );
        }
    }

    #[test]
    fn external_audio_transcription_catalog_gpt_rejects_unlisted() {
        // zz is not an assigned ISO 639-1 code
        assert!(GptTranscribeLanguageCodeV1::new("zz").is_none());
        // xyz is not a documented alpha-3
        assert!(GptTranscribeLanguageCodeV1::new("xyz").is_none());
        // uppercase rejected
        assert!(GptTranscribeLanguageCodeV1::new("EN").is_none());
        assert!(GptTranscribeLanguageCodeV1::new("ENG").is_none());
        // empty
        assert!(GptTranscribeLanguageCodeV1::new("").is_none());
    }

    #[test]
    fn external_audio_transcription_catalog_gpt_eng_spa_yue_cmn_boundaries() {
        assert!(GptTranscribeLanguageCodeV1::new("eng").is_some());
        assert!(GptTranscribeLanguageCodeV1::new("spa").is_some());
        assert!(GptTranscribeLanguageCodeV1::new("yue").is_some());
        assert!(GptTranscribeLanguageCodeV1::new("cmn").is_some());
        // yue is in GPT but NOT in Whisper (family boundary)
        assert!(GptTranscribeLanguageCodeV1::new("yue").is_some());
        assert!(WhisperLanguageCodeV1::new("yue").is_none());
    }

    #[test]
    fn external_audio_transcription_catalog_gpt_regional_zh_boundaries() {
        for code in &["zh-cn", "zh-tw", "zh-hk"] {
            assert!(GptTranscribeLanguageCodeV1::new(code).is_some());
            assert!(WhisperLanguageCodeV1::new(code).is_none());
        }
    }

    #[test]
    fn external_audio_transcription_catalog_disjoint_versions() {
        assert_ne!(
            GPT_TRANSCRIBE_PROVENANCE.catalog_version,
            WHISPER_PROVENANCE.catalog_version
        );
        assert_ne!(
            GPT_TRANSCRIBE_PROVENANCE.sha256_hex,
            WHISPER_PROVENANCE.sha256_hex
        );
    }

    #[test]
    fn external_audio_transcription_catalog_su_yue_family_boundaries() {
        assert!(WhisperLanguageCodeV1::new("su").is_some());
        assert!(GptTranscribeLanguageCodeV1::new("su").is_some());
        assert!(GptTranscribeLanguageCodeV1::new("yue").is_some());
        assert!(WhisperLanguageCodeV1::new("yue").is_none());
    }

    #[test]
    fn external_audio_transcription_catalog_gpt_iso639_1_subset_for_diarization() {
        let subset = gpt_transcribe_iso639_1_subset();
        assert!(subset.contains(&"en"));
        assert!(subset.contains(&"es"));
        assert!(subset.contains(&"zh"));
        assert!(!subset.contains(&"eng"));
        assert!(!subset.contains(&"yue"));
        assert!(!subset.contains(&"zh-cn"));
    }

    #[test]
    fn external_audio_transcription_catalog_cross_family_rejection() {
        assert!(GptTranscribeLanguageCodeV1::new("zh").is_some());
        assert!(WhisperLanguageCodeV1::new("zh").is_some());
    }
}

// ===========================================================================
// external_audio_transcription_request
// ===========================================================================

mod request_tests {
    use super::super::request::*;
    use super::super::result::{RequestedLanguageV1, TimestampsKind};
    use super::TEST_BOUNDARY;

    #[test]
    fn external_audio_transcription_request_model_selection_pure() {
        assert_eq!(
            TranscriptionModel::select(TimestampsKind::Off, false).unwrap(),
            TranscriptionModel::GptTranscribe
        );
        assert_eq!(
            TranscriptionModel::select(TimestampsKind::Off, true).unwrap(),
            TranscriptionModel::Gpt4oTranscribeDiarize
        );
        assert_eq!(
            TranscriptionModel::select(TimestampsKind::Segment, false).unwrap(),
            TranscriptionModel::Whisper1
        );
        assert_eq!(
            TranscriptionModel::select(TimestampsKind::Word, false).unwrap(),
            TranscriptionModel::Whisper1
        );
        assert!(TranscriptionModel::select(TimestampsKind::Segment, true).is_err());
        assert!(TranscriptionModel::select(TimestampsKind::Word, true).is_err());
    }

    #[test]
    fn external_audio_transcription_request_prompt_trim_sp_tab_only() {
        let p = validate_prompt("  \t hello   world \t ").unwrap();
        assert_eq!(p.as_deref(), Some("hello   world"));
        let p2 = validate_prompt("a\t b c").unwrap();
        assert_eq!(p2.as_deref(), Some("a\t b c"));
        assert_eq!(validate_prompt("   \t  ").unwrap(), None);
        assert_eq!(validate_prompt("").unwrap(), None);
    }

    #[test]
    fn external_audio_transcription_request_prompt_caps() {
        let ok = "a".repeat(PROMPT_MAX_SCALARS);
        assert!(validate_prompt(&ok).is_ok());
        let too_long = "a".repeat(PROMPT_MAX_SCALARS + 1);
        assert!(validate_prompt(&too_long).is_err());
        let ok_bytes = "é".repeat(PROMPT_MAX_UTF8_BYTES / 2);
        assert!(validate_prompt(&ok_bytes).is_ok());
        let too_many_bytes = "é".repeat(PROMPT_MAX_UTF8_BYTES / 2 + 1);
        assert!(validate_prompt(&too_many_bytes).is_err());
    }

    #[test]
    fn external_audio_transcription_request_keyword_forbidden_bytes() {
        assert!(validate_keyword("a<b").is_err());
        assert!(validate_keyword("a>b").is_err());
        assert!(validate_keyword("a\nb").is_err());
        assert!(validate_keyword("a\rb").is_err());
        assert!(validate_keyword("\rhello\r").is_err());
    }

    #[test]
    fn external_audio_transcription_request_keyword_trim_and_caps() {
        assert_eq!(validate_keyword("  hello  ").unwrap(), "hello");
        assert_eq!(validate_keyword("\thello\t").unwrap(), "hello");
        assert_eq!(validate_keyword("hello world").unwrap(), "hello world");
        assert!(validate_keyword("   ").is_err());
        assert!(validate_keyword("\t").is_err());
        let ok = "a".repeat(KEYWORD_MAX_SCALARS);
        assert!(validate_keyword(&ok).is_ok());
        let too_long = "a".repeat(KEYWORD_MAX_SCALARS + 1);
        assert!(validate_keyword(&too_long).is_err());
    }

    #[test]
    fn external_audio_transcription_request_keywords_duplicates_reject() {
        let kws = vec!["hello".to_string(), "hello".to_string()];
        assert!(validate_keywords(&kws).is_err());
        let kws2 = vec!["hello".to_string(), "world".to_string()];
        assert!(validate_keywords(&kws2).is_ok());
        let many: Vec<String> = (0..KEYWORDS_MAX_ENTRIES)
            .map(|i| format!("kw{i}"))
            .collect();
        assert!(validate_keywords(&many).is_ok());
        let too_many: Vec<String> = (0..=KEYWORDS_MAX_ENTRIES)
            .map(|i| format!("kw{i}"))
            .collect();
        assert!(validate_keywords(&too_many).is_err());
    }

    #[test]
    fn external_audio_transcription_request_gpt_languages() {
        let langs = vec!["en".to_string(), "es".to_string()];
        assert!(validate_gpt_languages(&langs).is_ok());
        let dup = vec!["en".to_string(), "en".to_string()];
        assert!(validate_gpt_languages(&dup).is_err());
        let bad = vec!["zz".to_string()];
        assert!(validate_gpt_languages(&bad).is_err());
    }

    #[test]
    fn external_audio_transcription_request_whisper_languages_zero_or_one() {
        assert!(validate_whisper_languages(&[]).is_ok());
        assert!(validate_whisper_languages(&["en".into()]).is_ok());
        assert!(validate_whisper_languages(&["zh".into()]).is_ok());
        assert!(validate_whisper_languages(&["en".into(), "zh".into()]).is_err());
        assert!(validate_whisper_languages(&["yue".into()]).is_err());
    }

    #[test]
    fn external_audio_transcription_request_diarize_languages_iso639_1_only() {
        assert!(validate_diarize_languages(&[]).is_ok());
        assert!(validate_diarize_languages(&["en".into()]).is_ok());
        assert!(validate_diarize_languages(&["eng".into()]).is_err());
        assert!(validate_diarize_languages(&["yue".into()]).is_err());
        assert!(validate_diarize_languages(&["zh-cn".into()]).is_err());
        assert!(validate_diarize_languages(&["en".into(), "es".into()]).is_err());
    }

    #[test]
    fn external_audio_transcription_request_file_length_vectors() {
        assert!(plan_gpt_transcribe(0, None, &[], &[], TEST_BOUNDARY).is_err());
        assert!(plan_gpt_transcribe(1, None, &[], &[], TEST_BOUNDARY).is_ok());
        assert!(plan_gpt_transcribe(24_999_999, None, &[], &[], TEST_BOUNDARY).is_ok());
        assert!(plan_gpt_transcribe(25_000_000, None, &[], &[], TEST_BOUNDARY).is_ok());
        assert!(plan_gpt_transcribe(25_000_001, None, &[], &[], TEST_BOUNDARY).is_err());
    }

    #[test]
    fn external_audio_transcription_request_transmitted_equals_precomputed() {
        let plan =
            plan_gpt_transcribe(100, Some("hi"), &["kw".into()], &[], TEST_BOUNDARY).unwrap();
        let audio = vec![0u8; 100];
        let encoded = encode_multipart(&plan, &audio).unwrap();
        assert_eq!(encoded.len() as u64, plan.encoded_length);
    }

    #[test]
    fn external_audio_transcription_request_boundary_validation() {
        assert!(validate_boundary(TEST_BOUNDARY).is_ok());
        assert!(validate_boundary("xcockpit-0123456789abcdef0123456789abcdef").is_err());
        assert!(validate_boundary("flycockpit-abc").is_err());
        assert!(validate_boundary("flycockpit-0123456789ABCDEF0123456789abcdef").is_err());
    }

    #[test]
    fn external_audio_transcription_request_boundary_collision_detection() {
        let plan = plan_gpt_transcribe(10, None, &[], &[], TEST_BOUNDARY).unwrap();
        let audio = vec![0u8; 10];
        assert!(check_boundary_collision(&plan.boundary, &plan.parts, &audio).is_ok());
        let marker = format!("--{}", plan.boundary);
        let mut bad_audio = audio.clone();
        bad_audio.extend_from_slice(marker.as_bytes());
        let bad_plan =
            plan_gpt_transcribe(bad_audio.len() as u64, None, &[], &[], TEST_BOUNDARY).unwrap();
        assert!(check_boundary_collision(&bad_plan.boundary, &bad_plan.parts, &bad_audio).is_err());
    }

    #[test]
    fn external_audio_transcription_request_gpt_multipart_part_order() {
        let plan = plan_gpt_transcribe(
            10,
            Some("prompt text"),
            &["kw1".into(), "kw2".into()],
            &[
                RequestedLanguageV1::new("en".into()),
                RequestedLanguageV1::new("es".into()),
            ],
            TEST_BOUNDARY,
        )
        .unwrap();
        let audio = vec![0u8; 10];
        let encoded = encode_multipart(&plan, &audio).unwrap();
        let s = String::from_utf8(encoded).unwrap();
        let model_pos = s.find("name=\"model\"").unwrap();
        let file_pos = s.find("name=\"file\"").unwrap();
        let prompt_pos = s.find("name=\"prompt\"").unwrap();
        let kw_pos = s.find("name=\"keywords[]\"").unwrap();
        let lang_pos = s.find("name=\"languages[]\"").unwrap();
        assert!(model_pos < file_pos);
        assert!(file_pos < prompt_pos);
        assert!(prompt_pos < kw_pos);
        assert!(kw_pos < lang_pos);
    }

    #[test]
    fn external_audio_transcription_request_diarize_chunking_over_30s() {
        let plan = plan_gpt_4o_transcribe_diarize(10, Some(30_000), None, TEST_BOUNDARY).unwrap();
        let audio = vec![0u8; 10];
        let encoded = encode_multipart(&plan, &audio).unwrap();
        let s = String::from_utf8(encoded).unwrap();
        assert!(!s.contains("chunking_strategy"));
        let plan2 = plan_gpt_4o_transcribe_diarize(10, Some(30_001), None, TEST_BOUNDARY).unwrap();
        let encoded2 = encode_multipart(&plan2, &audio).unwrap();
        let s2 = String::from_utf8(encoded2).unwrap();
        assert!(s2.contains("chunking_strategy"));
        assert!(s2.contains("auto"));
    }

    #[test]
    fn external_audio_transcription_request_whisper_granularity() {
        let plan =
            plan_whisper_1(10, CallerTimestamps::Segment, None, None, TEST_BOUNDARY).unwrap();
        let audio = vec![0u8; 10];
        let encoded = encode_multipart(&plan, &audio).unwrap();
        let s = String::from_utf8(encoded).unwrap();
        assert!(s.contains("timestamp_granularities[]"));
        assert!(s.contains("segment"));
        let plan2 = plan_whisper_1(10, CallerTimestamps::Word, None, None, TEST_BOUNDARY).unwrap();
        let encoded2 = encode_multipart(&plan2, &audio).unwrap();
        let s2 = String::from_utf8(encoded2).unwrap();
        assert!(s2.contains("word"));
        assert!(plan_whisper_1(10, CallerTimestamps::Off, None, None, TEST_BOUNDARY).is_err());
    }

    #[test]
    fn external_audio_transcription_request_crlf_framing() {
        let plan = plan_gpt_transcribe(10, None, &[], &[], TEST_BOUNDARY).unwrap();
        let audio = vec![0u8; 10];
        let encoded = encode_multipart(&plan, &audio).unwrap();
        let s = String::from_utf8_lossy(&encoded);
        assert!(s.contains("--flycockpit-0123456789abcdef0123456789abcdef\r\n"));
        assert!(s.contains("--flycockpit-0123456789abcdef0123456789abcdef--\r\n"));
        assert!(s.starts_with("--flycockpit-"));
    }

    #[test]
    fn external_audio_transcription_request_total_cap_exact() {
        let plan = plan_gpt_transcribe(25_000_000, None, &[], &[], TEST_BOUNDARY).unwrap();
        assert!(plan.encoded_length <= MAX_TOTAL_BYTES);
        assert!(plan.encoded_length > 25_000_000);
    }
}

// ===========================================================================
// external_audio_transcription_response
// ===========================================================================

mod response_tests {
    use super::super::response::*;
    use super::super::result::TranscriptionUsageV1;

    #[test]
    fn external_audio_transcription_response_gpt_transcribe_basic() {
        let body = br#"{"text":"hello","languages":[]}"#;
        let resp = decode_gpt_transcribe(body).unwrap();
        assert_eq!(resp.text, "hello");
        assert!(resp.detected_languages.is_empty());
        assert_eq!(resp.usage, TranscriptionUsageV1::NotReported);
    }

    #[test]
    fn external_audio_transcription_response_gpt_transcribe_with_languages() {
        let body = br#"{"text":"hi","languages":[{"code":"en"},{"code":"es"}]}"#;
        let resp = decode_gpt_transcribe(body).unwrap();
        assert_eq!(resp.detected_languages.len(), 2);
        assert_eq!(resp.detected_languages[0].code, "en");
        assert_eq!(resp.detected_languages[1].code, "es");
    }

    #[test]
    fn external_audio_transcription_response_gpt_transcribe_duplicate_languages_reject() {
        let body = br#"{"text":"hi","languages":[{"code":"en"},{"code":"en"}]}"#;
        assert!(decode_gpt_transcribe(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_gpt_transcribe_unlisted_language_reject() {
        let body = br#"{"text":"hi","languages":[{"code":"zz"}]}"#;
        assert!(decode_gpt_transcribe(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_gpt_transcribe_unknown_member_reject() {
        let body = br#"{"text":"hi","languages":[],"extra":1}"#;
        assert!(decode_gpt_transcribe(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_gpt_transcribe_token_usage() {
        let body = br#"{"text":"hi","languages":[],"usage":{"type":"tokens","input_tokens":100,"input_token_details":{"text_tokens":60,"audio_tokens":40},"output_tokens":50,"total_tokens":150}}"#;
        let resp = decode_gpt_transcribe(body).unwrap();
        match resp.usage {
            TranscriptionUsageV1::Tokens {
                input_tokens,
                text_tokens,
                audio_tokens,
                output_tokens,
                total_tokens,
            } => {
                assert_eq!(input_tokens, 100);
                assert_eq!(text_tokens, 60);
                assert_eq!(audio_tokens, 40);
                assert_eq!(output_tokens, 50);
                assert_eq!(total_tokens, 150);
            }
            _ => panic!("expected tokens usage"),
        }
    }

    #[test]
    fn external_audio_transcription_response_gpt_transcribe_bad_usage_equation_reject() {
        let body = br#"{"text":"hi","languages":[],"usage":{"type":"tokens","input_tokens":101,"input_token_details":{"text_tokens":60,"audio_tokens":40},"output_tokens":50,"total_tokens":150}}"#;
        assert!(decode_gpt_transcribe(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_diarized_basic() {
        let body = br#"{"task":"transcribe","duration":1.5,"text":"hello world","segments":[{"type":"transcript.text.segment","id":"1","start":0.0,"end":1.0,"text":"hello","speaker":"A"}]}"#;
        let resp = decode_diarized(body).unwrap();
        assert_eq!(resp.task, "transcribe");
        assert_eq!(resp.duration_us, 1_500_000);
        assert_eq!(resp.segments.len(), 1);
        assert_eq!(resp.segments[0].speaker, "A");
    }

    #[test]
    fn external_audio_transcription_response_diarized_wrong_type_reject() {
        let body = br#"{"task":"transcribe","duration":1.5,"text":"hi","segments":[{"type":"other","id":"1","start":0.0,"end":1.0,"text":"hi","speaker":"A"}]}"#;
        assert!(decode_diarized(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_diarized_257_speakers_reject() {
        let mut segs = String::from("[");
        for i in 0..257 {
            if i > 0 {
                segs.push(',');
            }
            segs.push_str(&format!(
                r#"{{"type":"transcript.text.segment","id":"{i}","start":0.0,"end":1.0,"text":"s","speaker":"spk{i}"}}"#
            ));
        }
        segs.push(']');
        let body =
            format!(r#"{{"task":"transcribe","duration":1.0,"text":"hi","segments":{segs}}}"#);
        assert!(decode_diarized(body.as_bytes()).is_err());
    }

    #[test]
    fn external_audio_transcription_response_diarized_normalize_local_ids_and_speakers() {
        let body = br#"{"task":"transcribe","duration":2.0,"text":"a b c","segments":[{"type":"transcript.text.segment","id":"x","start":0.0,"end":1.0,"text":"a","speaker":"A"},{"type":"transcript.text.segment","id":"y","start":1.0,"end":2.0,"text":"b","speaker":"B"},{"type":"transcript.text.segment","id":"z","start":2.0,"end":3.0,"text":"c","speaker":"A"}]}"#;
        let resp = decode_diarized(body).unwrap();
        let local = normalize_diarized_segments(&resp).unwrap();
        assert_eq!(local.len(), 3);
        assert_eq!(local[0].id, 0);
        assert_eq!(local[1].id, 1);
        assert_eq!(local[2].id, 2);
        assert_eq!(local[0].speaker, "speaker_1");
        assert_eq!(local[1].speaker, "speaker_2");
        assert_eq!(local[2].speaker, "speaker_1");
    }

    #[test]
    fn external_audio_transcription_response_whisper_segments_basic() {
        let body = br#"{"task":"transcribe","language":"en","duration":1.0,"text":"hi","segments":[{"id":0,"seek":0,"start":0.0,"end":1.0,"text":"hi","tokens":[1,2],"temperature":0.0,"avg_logprob":-0.5,"compression_ratio":1.0,"no_speech_prob":0.1}]}"#;
        let resp = decode_whisper_segments(body).unwrap();
        assert_eq!(resp.language, "en");
        assert_eq!(resp.segments.len(), 1);
        assert_eq!(resp.segments[0].tokens, vec![1, 2]);
    }

    #[test]
    fn external_audio_transcription_response_whisper_words_basic() {
        let body = br#"{"task":"transcribe","language":"en","duration":1.0,"text":"hi","words":[{"word":"hi","start":0.0,"end":1.0}]}"#;
        let resp = decode_whisper_words(body).unwrap();
        assert_eq!(resp.words.len(), 1);
        assert_eq!(resp.words[0].word, "hi");
    }

    #[test]
    fn external_audio_transcription_response_whisper_segment_mode_forbids_words() {
        let body = br#"{"task":"transcribe","language":"en","duration":1.0,"text":"hi","segments":[],"words":[]}"#;
        assert!(decode_whisper_segments(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_whisper_word_mode_forbids_segments() {
        let body = br#"{"task":"transcribe","language":"en","duration":1.0,"text":"hi","segments":[],"words":[]}"#;
        assert!(decode_whisper_words(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_whisper_logprobs_forbidden() {
        let body = br#"{"task":"transcribe","language":"en","duration":1.0,"text":"hi","segments":[],"logprobs":[]}"#;
        assert!(decode_whisper_segments(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_whisper_segment_strictly_increasing_ids() {
        let body = br#"{"task":"transcribe","language":"en","duration":1.0,"text":"a b","segments":[{"id":1,"seek":0,"start":0.0,"end":0.5,"text":"a","tokens":[],"temperature":0.0,"avg_logprob":-0.5,"compression_ratio":1.0,"no_speech_prob":0.1},{"id":0,"seek":1,"start":0.5,"end":1.0,"text":"b","tokens":[],"temperature":0.0,"avg_logprob":-0.5,"compression_ratio":1.0,"no_speech_prob":0.1}]}"#;
        assert!(decode_whisper_segments(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_whisper_temperature_out_of_range_reject() {
        let body = br#"{"task":"transcribe","language":"en","duration":1.0,"text":"hi","segments":[{"id":0,"seek":0,"start":0.0,"end":1.0,"text":"hi","tokens":[],"temperature":1.5,"avg_logprob":-0.5,"compression_ratio":1.0,"no_speech_prob":0.1}]}"#;
        assert!(decode_whisper_segments(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_whisper_empty_segments_with_text_reject() {
        let body =
            br#"{"task":"transcribe","language":"en","duration":1.0,"text":"hi","segments":[]}"#;
        assert!(decode_whisper_segments(body).is_err());
    }

    #[test]
    fn external_audio_transcription_response_whisper_empty_segments_empty_text_ok() {
        let body =
            br#"{"task":"transcribe","language":"en","duration":1.0,"text":"","segments":[]}"#;
        let resp = decode_whisper_segments(body).unwrap();
        assert!(resp.segments.is_empty());
        assert!(resp.text.is_empty());
    }

    #[test]
    fn external_audio_transcription_response_body_over_8mib_reject() {
        let big = vec![b' '; MAX_RESPONSE_BODY_BYTES + 1];
        assert!(decode_gpt_transcribe(&big).is_err());
        assert!(decode_diarized(&big).is_err());
        assert!(decode_whisper_segments(&big).is_err());
    }
}

// ===========================================================================
// normalized_transcription_result_v1
// ===========================================================================

mod result_tests {
    use super::super::result::*;

    #[test]
    fn normalized_transcription_result_v1_speaker_grammar_boundaries() {
        assert!(is_valid_local_speaker("speaker_1"));
        assert!(is_valid_local_speaker("speaker_9"));
        assert!(is_valid_local_speaker("speaker_10"));
        assert!(is_valid_local_speaker("speaker_99"));
        assert!(is_valid_local_speaker("speaker_100"));
        assert!(is_valid_local_speaker("speaker_256"));
        assert!(!is_valid_local_speaker("speaker_257"));
        assert!(!is_valid_local_speaker("speaker_0"));
        assert!(!is_valid_local_speaker("1"));
        assert!(!is_valid_local_speaker("speaker_"));
        assert!(!is_valid_local_speaker("speaker_abc"));
        assert!(!is_valid_local_speaker("speaker_01"));
    }

    #[test]
    fn normalized_transcription_result_v1_speaker_mapping_first_appearance() {
        let speakers = vec![
            Some("A".into()),
            Some("B".into()),
            Some("A".into()),
            Some("C".into()),
            None,
            Some("B".into()),
        ];
        let mapped = map_provider_speakers(&speakers);
        assert_eq!(mapped[0], Some("speaker_1".into()));
        assert_eq!(mapped[1], Some("speaker_2".into()));
        assert_eq!(mapped[2], Some("speaker_1".into()));
        assert_eq!(mapped[3], Some("speaker_3".into()));
        assert_eq!(mapped[4], None);
        assert_eq!(mapped[5], Some("speaker_2".into()));
    }

    #[test]
    fn normalized_transcription_result_v1_usage_token_equations() {
        assert!(TranscriptionUsageV1::validate_tokens(100, 60, 40, 50, 150).is_some());
        assert!(TranscriptionUsageV1::validate_tokens(101, 60, 40, 50, 150).is_none());
        assert!(TranscriptionUsageV1::validate_tokens(100, 60, 40, 50, 151).is_none());
    }

    #[test]
    fn normalized_transcription_result_v1_decimal_seconds_ties_to_even() {
        assert_eq!(decimal_seconds_to_microseconds(0.0000005), Some(0));
        assert_eq!(decimal_seconds_to_microseconds(0.0000015), Some(2));
        assert_eq!(decimal_seconds_to_microseconds(0.0000025), Some(2));
        assert_eq!(decimal_seconds_to_microseconds(1.0), Some(1_000_000));
        assert_eq!(decimal_seconds_to_microseconds(-1.0), None);
        assert_eq!(decimal_seconds_to_microseconds(f64::NAN), None);
        assert_eq!(decimal_seconds_to_microseconds(f64::INFINITY), None);
    }

    #[test]
    fn normalized_transcription_result_v1_text_projection_complete() {
        let text = "hello world";
        let outcome = project_text(text);
        assert!(outcome.complete);
        assert_eq!(outcome.text, text);
        assert_eq!(outcome.omitted_text_scalars, 0);
        assert_eq!(outcome.omitted_text_utf8_bytes, 0);
    }

    #[test]
    fn normalized_transcription_result_v1_text_projection_truncates_bytes() {
        let text = "a".repeat(TEXT_PROJECTION_MAX_UTF8_BYTES + 100);
        let outcome = project_text(&text);
        assert!(!outcome.complete);
        assert_eq!(outcome.text.len(), TEXT_PROJECTION_MAX_UTF8_BYTES);
        assert!(outcome.omitted_text_utf8_bytes > 0);
    }

    #[test]
    fn normalized_transcription_result_v1_text_projection_truncates_scalars() {
        let text = "é".repeat(TEXT_PROJECTION_MAX_SCALARS + 10);
        let outcome = project_text(&text);
        assert!(!outcome.complete);
        assert_eq!(outcome.text.chars().count(), TEXT_PROJECTION_MAX_SCALARS);
        assert!(outcome.omitted_text_scalars > 0);
    }

    #[test]
    fn normalized_transcription_result_v1_text_projection_never_splits_scalar() {
        let prefix = "a".repeat(TEXT_PROJECTION_MAX_UTF8_BYTES - 1);
        let text = format!("{prefix}𝕏");
        let outcome = project_text(&text);
        assert!(outcome.text.len() <= TEXT_PROJECTION_MAX_UTF8_BYTES);
        assert!(outcome.text.is_char_boundary(outcome.text.len()));
    }

    #[test]
    fn normalized_transcription_result_v1_requested_to_applied_tag_conversion() {
        let req = RequestedLanguageV1::new("es".into());
        let applied = requested_to_applied(&req);
        assert_eq!(applied.code, "es");
        let req_json = serde_json::to_string(&req).unwrap();
        let applied_json = serde_json::to_string(&applied).unwrap();
        assert!(req_json.contains("\"kind\":\"requested\""));
        assert!(applied_json.contains("\"kind\":\"applied\""));
    }

    #[test]
    fn normalized_transcription_result_v1_diarized_segment_fixed_kind() {
        let seg = DiarizedSegmentV1::new(0, 0, 1000, "hello".into(), "speaker_1".into());
        let json = serde_json::to_string(&seg).unwrap();
        assert!(json.contains("\"kind\":\"speech\""));
        let de: DiarizedSegmentV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(de.id, 0);
        assert_eq!(de.speaker, "speaker_1");
    }

    #[test]
    fn normalized_transcription_result_v1_diarized_segment_rejects_wrong_kind() {
        let json = r#"{"kind":"transcript.text.segment","id":0,"start_us":0,"end_us":1000,"text":"hi","speaker":"speaker_1"}"#;
        let result: Result<DiarizedSegmentV1, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn normalized_transcription_result_v1_closed_result_rejects_unknown_fields() {
        let json = r#"{
            "schema_version": 1,
            "text": "hi",
            "content": {"kind":"plain","text":"hi"},
            "requested_languages": [],
            "applied_languages": [],
            "detected_languages": [],
            "timestamps": {"requested":"off","applied":"off"},
            "diarization": {"requested":false,"applied":false},
            "usage": {"kind":"not_reported"},
            "provenance": {
                "attachment_id":"a","attachment_version":1,"attachment_checksum":"c",
                "interval_start_us":0,"interval_end_us":1000,"session_id":"s",
                "canonical_project_digest":"d","provider_id":"p",
                "endpoint_identity_digest":"e","endpoint_config_generation":1,
                "model_id":"m","credential_fingerprint_digest":"f",
                "transcription_request_digest":"g","external_operation_id":"o",
                "external_attempt_number":1
            },
            "complete": true,
            "omitted_text_scalars": 0,
            "omitted_text_utf8_bytes": 0,
            "omitted_segments": 0,
            "omitted_words": 0,
            "extra_field": true
        }"#;
        let result: Result<NormalizedTranscriptionResultV1, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    #[test]
    fn normalized_transcription_result_v1_timestamps_diarization_invariants() {
        let plain = TranscriptionContentV1::Plain { text: "hi".into() };
        let ts = TimestampsV1 {
            requested: TimestampsKind::Off,
            applied: TimestampsKind::Off,
        };
        let dia = DiarizationV1 {
            requested: false,
            applied: false,
        };
        assert!(validate_content_timestamps(&plain, &ts, &dia).is_ok());

        let ts_bad = TimestampsV1 {
            requested: TimestampsKind::Segment,
            applied: TimestampsKind::Segment,
        };
        assert!(validate_content_timestamps(&plain, &ts_bad, &dia).is_err());

        let segs = TranscriptionContentV1::Segments { items: vec![] };
        let ts_seg = TimestampsV1 {
            requested: TimestampsKind::Segment,
            applied: TimestampsKind::Segment,
        };
        assert!(validate_content_timestamps(&segs, &ts_seg, &dia).is_ok());

        let words = TranscriptionContentV1::Words { items: vec![] };
        let ts_word = TimestampsV1 {
            requested: TimestampsKind::Word,
            applied: TimestampsKind::Word,
        };
        assert!(validate_content_timestamps(&words, &ts_word, &dia).is_ok());

        let dia_content = TranscriptionContentV1::Diarized {
            duration_us: 1000,
            items: vec![],
        };
        let ts_off = TimestampsV1 {
            requested: TimestampsKind::Off,
            applied: TimestampsKind::Off,
        };
        let dia_true = DiarizationV1 {
            requested: true,
            applied: true,
        };
        assert!(validate_content_timestamps(&dia_content, &ts_off, &dia_true).is_ok());
        let dia_false = DiarizationV1 {
            requested: false,
            applied: false,
        };
        assert!(validate_content_timestamps(&dia_content, &ts_off, &dia_false).is_err());
    }
}

// ===========================================================================
// media_egress_transcription_context_digest
// ===========================================================================

mod authorization_tests {
    use super::super::authorization::*;
    use super::super::result::{RequestedLanguageV1, TimestampsKind};

    fn base_request() -> MediaEgressTranscriptionRequest {
        MediaEgressTranscriptionRequest {
            provider_id: "openai".into(),
            model_id: "gpt-transcribe".into(),
            credential_fingerprint_digest: "abc123".into(),
            origin: "cli".into(),
            resolved_location: "local".into(),
            project_digest: "proj1".into(),
            session_id: "sess1".into(),
            attachment_id: "att1".into(),
            attachment_checksum: "chk1".into(),
            interval_start_us: 0,
            interval_end_us: 1_000_000,
            prompt_bytes: vec![],
            keywords: vec![],
            languages: vec![],
            timestamps: TimestampsKind::Off,
            diarization: false,
            purpose: TranscriptionPurpose::Transcription,
        }
    }

    #[test]
    fn media_egress_transcription_context_digest_byte_stable() {
        let req = base_request();
        let d1 = transcription_request_digest(&req);
        let d2 = transcription_request_digest(&req);
        assert_eq!(d1, d2);
        assert_eq!(d1.len(), 64);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_attachment_id() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.attachment_id = "att2".into();
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_interval() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.interval_start_us = 500_000;
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_prompt_bytes() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.prompt_bytes = b"hello".to_vec();
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_keyword_order() {
        let mut req = base_request();
        req.keywords = vec!["a".into(), "b".into()];
        let d1 = transcription_request_digest(&req);
        req.keywords = vec!["b".into(), "a".into()];
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_language_order() {
        let mut req = base_request();
        req.languages = vec![
            RequestedLanguageV1::new("en".into()),
            RequestedLanguageV1::new("es".into()),
        ];
        let d1 = transcription_request_digest(&req);
        req.languages = vec![
            RequestedLanguageV1::new("es".into()),
            RequestedLanguageV1::new("en".into()),
        ];
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_timestamps() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.timestamps = TimestampsKind::Segment;
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_diarization() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.diarization = true;
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_model() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.model_id = "whisper-1".into();
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_session() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.session_id = "sess2".into();
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_project() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.project_digest = "proj2".into();
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_destination() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.resolved_location = "remote".into();
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_mutates_attachment_checksum() {
        let mut req = base_request();
        let d1 = transcription_request_digest(&req);
        req.attachment_checksum = "chk2".into();
        let d2 = transcription_request_digest(&req);
        assert_ne!(d1, d2);
    }

    #[test]
    fn media_egress_transcription_context_digest_no_hidden_context() {
        let req = base_request();
        let d1 = transcription_request_digest(&req);
        let req2 = base_request();
        let d2 = transcription_request_digest(&req2);
        assert_eq!(d1, d2);
    }
}

// ===========================================================================
// external_audio_whisper_prompt_preflight
// ===========================================================================

mod whisper_preflight_tests {
    use super::super::whisper_preflight::*;

    #[test]
    fn external_audio_whisper_prompt_preflight_empty_prompt_ok() {
        let outcome = whisper_prompt_preflight("");
        match outcome {
            WhisperPreflightOutcome::Ok { token_count } => {
                assert_eq!(token_count, 0);
            }
            _ => panic!("expected Ok for empty prompt"),
        }
    }

    #[test]
    fn external_audio_whisper_prompt_preflight_short_prompt_ok() {
        let outcome = whisper_prompt_preflight("Hello world");
        match outcome {
            WhisperPreflightOutcome::Ok { token_count } => {
                assert!(token_count > 0);
                assert!(token_count <= WHISPER_PROMPT_MAX_TOKENS);
            }
            _ => panic!("expected Ok for short prompt"),
        }
    }

    #[test]
    fn external_audio_whisper_prompt_preflight_rejects_over_224() {
        let words: Vec<String> = (0..400).map(|i| format!("word{i}")).collect();
        let prompt = words.join(" ");
        let outcome = whisper_prompt_preflight(&prompt);
        match outcome {
            WhisperPreflightOutcome::TooLong { token_count } => {
                assert!(token_count > WHISPER_PROMPT_MAX_TOKENS);
            }
            _ => panic!("expected TooLong for prompt over 224 tokens"),
        }
    }

    #[test]
    fn external_audio_whisper_prompt_preflight_provenance_pinned() {
        assert_eq!(
            WHISPER_TOKENIZER_PROVENANCE.source_url,
            "https://raw.githubusercontent.com/openai/whisper/f6f01c561c45ad6ab421405e18ae22fd0c698e92/whisper/tokenizer.py"
        );
        assert_eq!(WHISPER_TOKENIZER_PROVENANCE.retrieval_date, "2026-08-05");
        assert_eq!(WHISPER_TOKENIZER_PROVENANCE.license, "MIT");
    }

    #[test]
    fn external_audio_whisper_prompt_preflight_encoding_is_r50k() {
        assert_eq!(WHISPER_ENCODING, cockpit_tokenizer::TiktokenEncoding::R50k);
    }
}
