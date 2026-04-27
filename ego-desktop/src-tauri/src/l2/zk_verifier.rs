/// True ZK-STARK Verifier using RISC Zero (risc0-zkvm).
/// 
/// To compile this, ensure you add `risc0-zkvm = "1.0"` (or latest) 
/// and `bincode = "1.3"` to your `src-tauri/Cargo.toml`.

use risc0_zkvm::Receipt;

/// The expected RISC-V image ID for your Layer 2 Rollup program.
/// This must match the compiled ELF hash of your zkVM guest code.
/// Replace this placeholder with your actual guest ID constant.
pub const ROLLUP_IMAGE_ID: [u32; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

pub fn verify_stark(proof_bytes: &[u8], public_inputs: &[u8]) -> bool {
    if proof_bytes.is_empty() {
        tracing::warn!("[ZK-Rollup] Rejected empty STARK proof");
        return false;
    }

    // 1. Deserialize the cryptographic receipt (proof + journal)
    let receipt: Receipt = match bincode::deserialize(proof_bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("[ZK-Rollup] Failed to deserialize STARK receipt: {}", e);
            return false;
        }
    };

    // 2. Cryptographically verify the STARK proof against the authorized Rollup VM image
    if let Err(e) = receipt.verify(ROLLUP_IMAGE_ID) {
        tracing::error!("[ZK-Rollup] STARK proof verification failed: {}", e);
        return false;
    }

    // 3. Ensure the VM execution actually operated on the exact state roots we expect
    // In our L2 architecture, public_inputs = "pre_state_root:post_state_root"
    let journal_bytes = receipt.journal.bytes.as_slice();
    if journal_bytes != public_inputs {
        tracing::error!(
            "[ZK-Rollup] Public inputs mismatch! VM committed to different state roots."
        );
        return false;
    }

    tracing::info!("[ZK-Rollup] STARK proof verified successfully for L2 batch");
    true
}