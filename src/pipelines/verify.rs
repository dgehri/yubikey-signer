//! `VerifyWorkflow`: high-level facade for verifying signed PE files.
//!
//! Delegates to `VerificationService`; keeps symmetry with sign & timestamp workflows.

use crate::{
    domain::verification::VerificationReport, services::verification::VerificationService,
    SigningResult,
};

/// Orchestrates verification steps for a signed PE file.
pub struct VerifyWorkflow {
    svc: VerificationService,
}

impl Default for VerifyWorkflow {
    fn default() -> Self {
        Self::new()
    }
}

impl VerifyWorkflow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            svc: VerificationService::new(),
        }
    }

    /// Run verification over provided signed PE bytes.
    pub fn run(&self, signed_pe: &[u8]) -> SigningResult<VerificationReport> {
        self.svc.verify(signed_pe)
    }
}
