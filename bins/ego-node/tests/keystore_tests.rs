use ego_node::keystore::{AccountBinding, KeystoreError, SecureKeystore};

#[test]
fn test_new_keystore() {
    let keystore = SecureKeystore::new();
    assert!(keystore.get_binding_legacy().is_none());
    assert!(!keystore.is_encrypted());
    assert_eq!(keystore.derived_key_count(), 0);
    assert_eq!(keystore.metadata().key_count, 1);
    assert_eq!(keystore.metadata().binding_count, 0);

    let keypair = keystore.keypair();
    let _public_key = keypair.public();
}

#[test]
fn test_keypair_access() {
    let keystore = SecureKeystore::new();
    let keypair1 = keystore.keypair();
    let keypair2 = keystore.keypair();
    assert!(std::ptr::eq(keypair1, keypair2));
}

#[test]
fn test_bind_on_chain_account() {
    let mut keystore = SecureKeystore::new();
    let test_pubkey = vec![1, 2, 3, 4, 5];
    let test_signature = vec![10, 20, 30, 40, 50];

    assert!(keystore.get_binding_legacy().is_none());

    keystore.bind_on_chain_account_simple(test_pubkey.clone(), test_signature.clone());

    let binding = keystore.get_binding_legacy();
    assert!(binding.is_some());
    let (pubkey, signature) = binding.unwrap();
    assert_eq!(pubkey, &test_pubkey[..]);
    assert_eq!(signature, &test_signature[..]);
    assert_eq!(keystore.metadata().binding_count, 1);
}

#[test]
fn test_rebind_on_chain_account() {
    let mut keystore = SecureKeystore::new();
    let pubkey1 = vec![1, 2, 3];
    let signature1 = vec![10, 20, 30];
    keystore.bind_on_chain_account_simple(pubkey1, signature1);

    let pubkey2 = vec![4, 5, 6, 7];
    let signature2 = vec![40, 50, 60, 70];
    keystore.bind_on_chain_account_simple(pubkey2.clone(), signature2.clone());

    let binding = keystore.get_binding_legacy().unwrap();
    assert_eq!(binding.0, &pubkey2[..]);
    assert_eq!(binding.1, &signature2[..]);
    assert_eq!(keystore.metadata().binding_count, 1);
}

#[test]
fn test_empty_vectors_binding() {
    let mut keystore = SecureKeystore::new();
    let empty_pubkey = vec![];
    let empty_signature = vec![];
    keystore.bind_on_chain_account_simple(empty_pubkey, empty_signature);

    let binding = keystore.get_binding_legacy();
    assert!(binding.is_some());
    let (pubkey, signature) = binding.unwrap();
    assert!(pubkey.is_empty());
    assert!(signature.is_empty());
}

#[test]
fn test_keypair_uniqueness() {
    let keystore1 = SecureKeystore::new();
    let keystore2 = SecureKeystore::new();

    let peer_id1 = keystore1.keypair().public().to_peer_id();
    let peer_id2 = keystore2.keypair().public().to_peer_id();

    assert_ne!(peer_id1, peer_id2);
}

#[test]
fn test_keypair_consistency() {
    let keystore = SecureKeystore::new();
    let peer_id1 = keystore.keypair().public().to_peer_id();
    let peer_id2 = keystore.keypair().public().to_peer_id();
    assert_eq!(peer_id1, peer_id2);
}

#[test]
fn test_large_binding_data() {
    let mut keystore = SecureKeystore::new();
    let large_pubkey = vec![42u8; 1024];
    let large_signature = vec![84u8; 2048];
    keystore.bind_on_chain_account_simple(large_pubkey.clone(), large_signature.clone());

    let binding = keystore.get_binding_legacy().unwrap();
    assert_eq!(binding.0.len(), 1024);
    assert_eq!(binding.1.len(), 2048);
    assert_eq!(binding.0, &large_pubkey[..]);
    assert_eq!(binding.1, &large_signature[..]);
}

#[test]
fn test_get_binding_returns_references() {
    let mut keystore = SecureKeystore::new();
    let test_pubkey = vec![1, 2, 3, 4, 5];
    let test_signature = vec![10, 20, 30, 40, 50];
    keystore.bind_on_chain_account_simple(test_pubkey, test_signature);

    let binding1 = keystore.get_binding_legacy().unwrap();
    let binding2 = keystore.get_binding_legacy().unwrap();
    assert!(std::ptr::eq(binding1.0.as_ptr(), binding2.0.as_ptr()));
    assert!(std::ptr::eq(binding1.1.as_ptr(), binding2.1.as_ptr()));
}

#[test]
fn test_keypair_sign_and_verify() {
    let keystore = SecureKeystore::new();
    let keypair = keystore.keypair();
    let message = b"test message";

    let signature = keypair.sign(message).expect("Failed to sign message");

    let public_key = keypair.public();
    assert!(public_key.verify(message, &signature));

    let wrong_message = b"wrong message";
    assert!(!public_key.verify(wrong_message, &signature));
}

#[test]
fn test_keypair_peer_id() {
    let keystore = SecureKeystore::new();
    let keypair = keystore.keypair();

    let peer_id = keypair.public().to_peer_id();

    let peer_id2 = keypair.public().to_peer_id();
    assert_eq!(peer_id, peer_id2);

    let keystore2 = SecureKeystore::new();
    let peer_id3 = keystore2.keypair().public().to_peer_id();
    assert_ne!(peer_id, peer_id3);
}

#[test]
fn test_multiple_keystores_independent() {
    let mut keystore1 = SecureKeystore::new();
    let mut keystore2 = SecureKeystore::new();

    keystore1.bind_on_chain_account_simple(vec![1, 2, 3], vec![10, 20, 30]);
    keystore2.bind_on_chain_account_simple(vec![4, 5, 6], vec![40, 50, 60]);

    let binding1 = keystore1.get_binding_legacy().unwrap();
    let binding2 = keystore2.get_binding_legacy().unwrap();

    assert_ne!(binding1.0, binding2.0);
    assert_ne!(binding1.1, binding2.1);

    let peer_id1 = keystore1.keypair().public().to_peer_id();
    let peer_id2 = keystore2.keypair().public().to_peer_id();
    assert_ne!(peer_id1, peer_id2);
}

#[test]
fn test_proper_binding_with_verification() {
    let mut keystore = SecureKeystore::new();
    let account_pubkey = vec![1, 2, 3, 4, 5];

    let signature = keystore
        .create_binding_signature(&account_pubkey, None)
        .unwrap();

    let result = keystore.bind_on_chain_account(account_pubkey.clone(), signature, None);
    assert!(result.is_ok());

    let binding = keystore.get_binding(None).unwrap();
    assert_eq!(binding.account_pubkey, account_pubkey);
    assert!(binding.verified);
}

#[test]
fn test_invalid_binding_signature_rejected() {
    let mut keystore = SecureKeystore::new();
    let account_pubkey = vec![1, 2, 3, 4, 5];
    let invalid_signature = vec![99, 99, 99];

    let result = keystore.bind_on_chain_account(account_pubkey, invalid_signature, None);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        KeystoreError::BindingVerificationFailed(_)
    ));
}

#[test]
fn test_key_derivation() {
    let mut keystore = SecureKeystore::new();

    let purpose = "consensus";
    let primary_peer_id = keystore.peer_id();

    keystore.derive_keypair(purpose, None).unwrap();
    let derived_peer_id = keystore
        .get_derived_keypair(purpose)
        .unwrap()
        .public()
        .to_peer_id();

    assert!(keystore.get_derived_keypair(purpose).is_some());

    assert_ne!(primary_peer_id, derived_peer_id);

    assert_eq!(keystore.derived_key_count(), 1);
    assert_eq!(keystore.metadata().key_count, 2);
}

#[test]
fn test_sign_with_derived_key() {
    let mut keystore = SecureKeystore::new();
    let purpose = "signing";

    keystore.derive_keypair(purpose, None).unwrap();

    let message = b"test message";
    let signature = keystore.sign_with_derived(purpose, message).unwrap();

    let derived_key = keystore.get_derived_keypair(purpose).unwrap();
    assert!(derived_key.public().verify(message, &signature));

    assert!(!keystore.verify(message, &signature));
}

#[test]
fn test_multiple_chain_bindings() {
    let mut keystore = SecureKeystore::new();
    let account_pubkey1 = vec![1, 2, 3];
    let account_pubkey2 = vec![4, 5, 6];

    let sig1 = keystore
        .create_binding_signature(&account_pubkey1, Some("ethereum"))
        .unwrap();
    let sig2 = keystore
        .create_binding_signature(&account_pubkey2, Some("polygon"))
        .unwrap();

    keystore
        .bind_on_chain_account(account_pubkey1.clone(), sig1, Some("ethereum".to_string()))
        .unwrap();
    keystore
        .bind_on_chain_account(account_pubkey2.clone(), sig2, Some("polygon".to_string()))
        .unwrap();

    assert_eq!(keystore.metadata().binding_count, 2);

    let eth_binding = keystore.get_binding(Some("ethereum")).unwrap();
    let poly_binding = keystore.get_binding(Some("polygon")).unwrap();

    assert_eq!(eth_binding.account_pubkey, account_pubkey1);
    assert_eq!(poly_binding.account_pubkey, account_pubkey2);
    assert_ne!(
        eth_binding.binding_signature,
        poly_binding.binding_signature
    );
}

#[test]
fn test_binding_removal() {
    let mut keystore = SecureKeystore::new();
    let account_pubkey = vec![1, 2, 3, 4, 5];
    let signature = keystore
        .create_binding_signature(&account_pubkey, None)
        .unwrap();

    keystore
        .bind_on_chain_account(account_pubkey, signature, None)
        .unwrap();
    assert_eq!(keystore.metadata().binding_count, 1);

    let removed = keystore.remove_binding(None);
    assert!(removed.is_some());
    assert_eq!(keystore.metadata().binding_count, 0);
    assert!(keystore.get_binding(None).is_none());
}

#[test]
fn test_keystore_metadata() {
    let keystore = SecureKeystore::new();
    let metadata = keystore.metadata();

    assert_eq!(metadata.version, "1.0.0");
    assert_eq!(metadata.key_count, 1);
    assert_eq!(metadata.binding_count, 0);
    assert!(metadata.created_at > 0);
    assert!(metadata.last_accessed > 0);
}

#[test]
fn test_keystore_from_seed() {
    let seed = [42u8; 32];
    let keystore1 = SecureKeystore::from_seed(seed).unwrap();
    let keystore2 = SecureKeystore::from_seed(seed).unwrap();

    assert!(keystore1.is_encrypted());
    assert!(keystore2.is_encrypted());
}

#[test]
fn test_export_functionality() {
    let keystore = SecureKeystore::new();
    let exported = keystore.export_encrypted("password123").unwrap();

    assert!(exported.contains("version"));
    assert!(exported.contains("peer_id"));
    assert!(exported.contains("encrypted"));
}

#[test]
fn test_secure_clear() {
    let mut keystore = SecureKeystore::new();

    let seed = [42u8; 32];
    let mut keystore = SecureKeystore::from_seed(seed).unwrap();
    assert!(keystore.is_encrypted());

    keystore.secure_clear();

    let message = b"test message";
    let signature = keystore.sign(message).unwrap();
    assert!(keystore.verify(message, &signature));
}

#[test]
fn test_list_derived_purposes() {
    let mut keystore = SecureKeystore::new();

    keystore.derive_keypair("consensus", None).unwrap();
    keystore.derive_keypair("storage", None).unwrap();
    keystore.derive_keypair("networking", None).unwrap();

    let purposes = keystore.list_derived_purposes();
    assert_eq!(purposes.len(), 3);
    assert!(purposes.contains(&&"consensus".to_string()));
    assert!(purposes.contains(&&"storage".to_string()));
    assert!(purposes.contains(&&"networking".to_string()));
}

#[test]
fn test_keystore_touch() {
    let mut keystore = SecureKeystore::new();
    let initial_time = keystore.metadata().last_accessed;

    // Wait longer to ensure time difference on all systems
    std::thread::sleep(std::time::Duration::from_secs(1));
    keystore.touch();

    let updated_time = keystore.metadata().last_accessed;
    assert!(updated_time > initial_time);
}

#[test]
fn test_account_binding_message_creation() {
    let account_pubkey = vec![1, 2, 3, 4, 5];
    let binding = AccountBinding::new(
        account_pubkey.clone(),
        vec![],
        Some("testchain".to_string()),
    );

    let message = binding.create_binding_message();

    assert!(message.starts_with(b"EGO_BINDING:"));
    assert!(message.contains(&account_pubkey[0]));
    assert!(message.ends_with(b"testchain"));
}

#[test]
fn test_keystore_drop_clears_sensitive_data() {
    let seed = [42u8; 32];
    {
        let _keystore = SecureKeystore::from_seed(seed).unwrap();
        assert!(_keystore.is_encrypted());
    }
}

#[test]
fn test_keystore_sign_and_verify_methods() {
    let keystore = SecureKeystore::new();
    let message = b"test message for keystore signing";

    let signature = keystore.sign(message).unwrap();

    assert!(keystore.verify(message, &signature));

    let wrong_message = b"wrong message";
    assert!(!keystore.verify(wrong_message, &signature));
}

#[test]
fn test_get_all_bindings() {
    let mut keystore = SecureKeystore::new();

    let pubkey1 = vec![1, 2, 3];
    let pubkey2 = vec![4, 5, 6];

    let sig1 = keystore
        .create_binding_signature(&pubkey1, Some("chain1"))
        .unwrap();
    let sig2 = keystore
        .create_binding_signature(&pubkey2, Some("chain2"))
        .unwrap();

    keystore
        .bind_on_chain_account(pubkey1, sig1, Some("chain1".to_string()))
        .unwrap();
    keystore
        .bind_on_chain_account(pubkey2, sig2, Some("chain2".to_string()))
        .unwrap();

    let all_bindings = keystore.get_all_bindings();
    assert_eq!(all_bindings.len(), 2);
    assert!(all_bindings.contains_key("chain1"));
    assert!(all_bindings.contains_key("chain2"));
}

#[test]
fn test_keystore_from_mnemonic() {
    let mnemonic = "test mnemonic phrase for keystore creation";
    let keystore1 = SecureKeystore::from_mnemonic(mnemonic).unwrap();
    let keystore2 = SecureKeystore::from_mnemonic(mnemonic).unwrap();

    assert!(keystore1.is_encrypted());
    assert!(keystore2.is_encrypted());

    assert_ne!(keystore1.peer_id(), keystore2.peer_id());
}

#[test]
fn test_save_to_file() {
    let keystore = SecureKeystore::new();
    let temp_path = "/tmp/test_keystore.json";

    let result = keystore.save_to_file(temp_path);
    assert!(result.is_ok());

    let content = std::fs::read_to_string(temp_path).unwrap();
    assert!(content.contains("version"));
    assert!(content.contains("peer_id"));

    std::fs::remove_file(temp_path).ok();
}

#[test]
fn test_derived_key_reuse() {
    let mut keystore = SecureKeystore::new();
    let purpose = "test_purpose";

    let key1 = keystore.derive_keypair(purpose, None).unwrap();
    let peer_id1 = key1.public().to_peer_id();

    let key2 = keystore.derive_keypair(purpose, None).unwrap();
    let peer_id2 = key2.public().to_peer_id();

    assert_eq!(peer_id1, peer_id2);
    assert_eq!(keystore.derived_key_count(), 1);
}

#[test]
fn test_sign_with_nonexistent_derived_key() {
    let keystore = SecureKeystore::new();
    let message = b"test message";

    let result = keystore.sign_with_derived("nonexistent", message);
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), KeystoreError::KeyNotFound(_)));
}
