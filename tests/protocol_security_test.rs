//! Protocol Security Integration Tests
//!
//! Tests for consensus verification, certificate parsing, cell parsing,
//! relay family validation, traffic shaping, and flow control.
//!
//! Run with: wasm-pack test --headless --chrome

#![cfg(target_arch = "wasm32")]

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// ===== Consensus Verification Tests =====

#[wasm_bindgen_test]
fn known_authorities_count() {
    use tor_wasm::protocol::{DIRECTORY_AUTHORITIES, MIN_AUTHORITY_SIGNATURES};
    assert_eq!(DIRECTORY_AUTHORITIES.len(), 9);
    assert!(MIN_AUTHORITY_SIGNATURES <= DIRECTORY_AUTHORITIES.len());
}

#[wasm_bindgen_test]
fn authority_fingerprint_format() {
    use tor_wasm::protocol::DIRECTORY_AUTHORITIES;
    for auth in DIRECTORY_AUTHORITIES {
        assert_eq!(
            auth.v3ident.len(),
            40,
            "Authority {} has wrong fingerprint length",
            auth.name
        );
        assert!(
            auth.v3ident.chars().all(|c| c.is_ascii_hexdigit()),
            "Authority {} has non-hex fingerprint",
            auth.name
        );
    }
}

#[wasm_bindgen_test]
fn authority_lookup_case_insensitive() {
    use tor_wasm::protocol::{ConsensusVerifier, DIRECTORY_AUTHORITIES};
    let verifier = ConsensusVerifier::new();
    let fp = DIRECTORY_AUTHORITIES[0].v3ident;
    assert!(verifier.is_authority(fp));
    assert!(verifier.is_authority(&fp.to_lowercase()));
}

#[wasm_bindgen_test]
fn unknown_fingerprint_rejected() {
    use tor_wasm::protocol::ConsensusVerifier;
    let verifier = ConsensusVerifier::new();
    assert!(!verifier.is_authority("0000000000000000000000000000000000000000"));
    assert!(!verifier.is_authority("short"));
}

#[wasm_bindgen_test]
fn parse_consensus_signatures() {
    use tor_wasm::protocol::ConsensusVerifier;
    let consensus = r#"
network-status-version 3
valid-after 2024-01-01 00:00:00
directory-signature sha256 D586D18309DED4CD6D57C18FDB97EFA96D330566 ABCDEF1234
-----BEGIN SIGNATURE-----
dGVzdA==
-----END SIGNATURE-----
directory-signature sha256 14C131DFC5C6F93646BE72FA1401C02A8DF2E8B4 FEDCBA4321
-----BEGIN SIGNATURE-----
dGVzdDI=
-----END SIGNATURE-----
"#;
    let verifier = ConsensusVerifier::new();
    let sigs = verifier.parse_signatures(consensus);
    assert_eq!(sigs.len(), 2);
    assert_eq!(sigs[0].algorithm, "sha256");
    assert_eq!(sigs[0].identity, "D586D18309DED4CD6D57C18FDB97EFA96D330566");
}

#[wasm_bindgen_test]
fn empty_consensus_rejected() {
    use tor_wasm::protocol::ConsensusVerifier;
    let verifier = ConsensusVerifier::new();
    assert!(verifier.verify_consensus("").is_err());
}

#[wasm_bindgen_test]
fn consensus_digest_computation() {
    use tor_wasm::protocol::ConsensusVerifier;
    let consensus = "some data here\ndirectory-signature sha256 AABB 1234\n-----BEGIN SIGNATURE-----\nABC=\n-----END SIGNATURE-----\n";
    let verifier = ConsensusVerifier::new();

    let sha256 = verifier.compute_consensus_digest(consensus, "sha256");
    assert!(sha256.is_some());
    assert_eq!(sha256.unwrap().len(), 32); // SHA-256

    let sha1 = verifier.compute_consensus_digest(consensus, "sha1");
    assert!(sha1.is_some());
    assert_eq!(sha1.unwrap().len(), 20); // SHA-1
}

// ===== Certificate Parsing Tests =====

#[wasm_bindgen_test]
fn empty_certs_cell_rejected() {
    use tor_wasm::protocol::CertsCell;
    assert!(CertsCell::parse(&[]).is_err());
}

#[wasm_bindgen_test]
fn zero_certs_cell() {
    use tor_wasm::protocol::CertsCell;
    let cell = CertsCell::parse(&[0u8]).unwrap();
    assert_eq!(cell.certificates.len(), 0);
}

#[wasm_bindgen_test]
fn truncated_certs_cell_rejected() {
    use tor_wasm::protocol::CertsCell;
    assert!(CertsCell::parse(&[1u8]).is_err()); // Says 1 cert but no data
}

#[wasm_bindgen_test]
fn ed25519_cert_too_short() {
    use tor_wasm::protocol::Ed25519Certificate;
    assert!(Ed25519Certificate::parse(&[0u8; 50]).is_err());
}

#[wasm_bindgen_test]
fn ed25519_cert_wrong_version() {
    use tor_wasm::protocol::Ed25519Certificate;
    let mut data = vec![0u8; 110];
    data[0] = 0x02; // Wrong version
    assert!(Ed25519Certificate::parse(&data).is_err());
}

#[wasm_bindgen_test]
fn ed25519_cert_parse_valid() {
    use tor_wasm::protocol::Ed25519Certificate;
    let mut data = vec![0u8; 104];
    data[0] = 0x01; // Version
    data[1] = 0x04; // Type (signing key)
    data[2..6].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF]); // Far future
    data[6] = 0x01; // Cert key type
    data[39] = 0; // N_EXTENSIONS = 0

    let cert = Ed25519Certificate::parse(&data).unwrap();
    assert_eq!(cert.version, 1);
    assert_eq!(cert.cert_type, 4);
}

#[wasm_bindgen_test]
fn cert_verifier_quick_check() {
    use tor_wasm::protocol::{CertificateVerifier, CertsCell};

    let mut cert_data = vec![0u8; 104];
    cert_data[0] = 0x01;
    cert_data[1] = 0x04;
    cert_data[2..6].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF]);
    cert_data[6] = 0x01;
    cert_data[39] = 0;

    let cert_len = cert_data.len() as u16;
    let mut certs_cell_data = vec![1u8];
    certs_cell_data.push(4);
    certs_cell_data.extend_from_slice(&cert_len.to_be_bytes());
    certs_cell_data.extend_from_slice(&cert_data);

    let parsed = CertsCell::parse(&certs_cell_data).unwrap();
    let verifier = CertificateVerifier::new();
    assert!(verifier.quick_verify(&parsed).is_ok());
}

// ===== Cell Parsing Tests =====

#[wasm_bindgen_test]
fn cell_roundtrip() {
    use tor_wasm::protocol::{Cell, CellCommand};
    let payload = vec![0xAB; 100];
    let cell = Cell::new(0x12345678, CellCommand::Relay, payload.clone());
    let bytes = cell.to_bytes().unwrap();
    assert_eq!(bytes.len(), 514);

    let parsed = Cell::from_bytes(&bytes).unwrap();
    assert_eq!(parsed.circuit_id, 0x12345678);
    assert_eq!(&parsed.payload[..100], &payload[..]);
}

#[wasm_bindgen_test]
fn relay_command_values() {
    use tor_wasm::protocol::RelayCommand;
    assert_eq!(RelayCommand::Begin as u8, 1);
    assert_eq!(RelayCommand::Data as u8, 2);
    assert_eq!(RelayCommand::End as u8, 3);
    assert_eq!(RelayCommand::Connected as u8, 4);
    assert_eq!(RelayCommand::Sendme as u8, 5);
}

#[wasm_bindgen_test]
fn cell_command_values() {
    use tor_wasm::protocol::CellCommand;
    assert_eq!(CellCommand::Padding as u8, 0);
    assert_eq!(CellCommand::Create as u8, 1);
    assert_eq!(CellCommand::Created as u8, 2);
    assert_eq!(CellCommand::Relay as u8, 3);
    assert_eq!(CellCommand::Destroy as u8, 4);
}

#[wasm_bindgen_test]
fn relay_cell_max_data_size() {
    use tor_wasm::protocol::RelayCell;
    assert_eq!(RelayCell::MAX_DATA_SIZE, 498);
}

// ===== Relay Family Tests =====

#[wasm_bindgen_test]
fn family_same_relay_rejected() {
    use tor_wasm::relay_verifier::RelayVerifier;
    let verifier = RelayVerifier::new();
    assert!(verifier.validate_path("FP_A", "FP_A", "FP_C").is_err());
}

#[wasm_bindgen_test]
fn family_no_conflict() {
    use tor_wasm::relay_verifier::RelayVerifier;
    let verifier = RelayVerifier::new();
    assert!(verifier.validate_path("FP_A", "FP_B", "FP_C").is_ok());
}

#[wasm_bindgen_test]
fn deny_list_blocks_relay() {
    use tor_wasm::relay_verifier::RelayVerifier;
    let mut verifier = RelayVerifier::new();
    verifier.deny_relay("BAD_FP", "Known malicious");

    assert!(verifier.validate_path("BAD_FP", "B", "C").is_err());
    assert!(verifier.validate_path("A", "BAD_FP", "C").is_err());
    assert!(verifier.validate_path("A", "B", "BAD_FP").is_err());
    assert!(verifier.validate_path("A", "B", "C").is_ok());
}

// ===== Traffic Shaping Tests =====

#[wasm_bindgen_test]
fn traffic_shaping_default_has_padding() {
    use tor_wasm::traffic_shaping::TrafficShapingConfig;
    let config = TrafficShapingConfig::default();
    assert!(config.padding_enabled);
    assert!(!config.chaff_enabled);
}

#[wasm_bindgen_test]
fn traffic_shaping_disabled() {
    use tor_wasm::traffic_shaping::TrafficShapingConfig;
    let config = TrafficShapingConfig::disabled();
    assert!(!config.padding_enabled);
    assert_eq!(config.padding_probability, 0.0);
}

#[wasm_bindgen_test]
fn traffic_shaping_paranoid() {
    use tor_wasm::traffic_shaping::TrafficShapingConfig;
    let config = TrafficShapingConfig::paranoid();
    assert!(config.padding_enabled);
    assert!(config.chaff_enabled);
    assert!(config.min_cell_interval_ms > 0);
}

#[wasm_bindgen_test]
fn padding_cell_format() {
    use tor_wasm::traffic_shaping::TrafficShaper;
    let cell = TrafficShaper::create_padding_cell(0x12345678);
    assert_eq!(cell.len(), 514);
    assert_eq!(cell[4], 0); // PADDING command
    let circ_id = u32::from_be_bytes([cell[0], cell[1], cell[2], cell[3]]);
    assert_eq!(circ_id, 0x12345678);
}

#[wasm_bindgen_test]
fn padding_disabled_never_pads() {
    use tor_wasm::traffic_shaping::{TrafficShaper, TrafficShapingConfig};
    let mut shaper = TrafficShaper::new(TrafficShapingConfig::disabled());
    for _ in 0..100 {
        assert!(!shaper.should_add_padding());
    }
}

// ===== Flow Control Tests =====

#[wasm_bindgen_test]
fn flow_control_initial_window() {
    use tor_wasm::protocol::StreamFlowControl;
    let fc = StreamFlowControl::new(1);
    assert!(fc.can_send());
}

#[wasm_bindgen_test]
fn flow_control_sendme_trigger() {
    use tor_wasm::protocol::StreamFlowControl;
    let mut fc = StreamFlowControl::new(1);
    let mut triggered = false;
    for _ in 0..50 {
        if fc.on_receive_data() {
            triggered = true;
        }
    }
    assert!(triggered, "Should trigger SENDME after 50 received cells");
}

#[wasm_bindgen_test]
fn flow_control_window_exhaustion() {
    use tor_wasm::protocol::StreamFlowControl;
    let mut fc = StreamFlowControl::new(1);
    for _ in 0..500 {
        assert!(fc.can_send());
        let _ = fc.on_send();
    }
    assert!(!fc.can_send());
}

#[wasm_bindgen_test]
fn flow_control_sendme_replenish() {
    use tor_wasm::protocol::StreamFlowControl;
    let mut fc = StreamFlowControl::new(1);
    for _ in 0..500 {
        let _ = fc.on_send();
    }
    assert!(!fc.can_send());
    fc.on_sendme_received();
    assert!(fc.can_send());
}
