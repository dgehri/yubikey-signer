//! Workflow pipelines orchestrating stateless services.

#[cfg(feature = "pcsc-backend")]
pub mod sign;
pub mod timestamp;
pub mod verify;
