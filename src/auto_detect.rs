//! Auto-detection module for YubiKey slots and certificates
//!
//! This module provides intelligent discovery of available PIV slots,
//! certificates, and automatically suggests the best options for code signing.

use crate::cert_validator::{CertificateAnalysis, CertificateValidator};
use crate::error::SigningResult;
use crate::types::PivSlot;
use crate::yubikey_ops::YubiKeyOperations;
use std::collections::HashMap;
use x509_cert::Certificate;

/// Information about a discovered PIV slot
#[derive(Debug, Clone)]
pub struct SlotInfo {
    /// PIV slot identifier
    pub slot: PivSlot,
    /// Whether a certificate is present in this slot
    pub has_certificate: bool,
    /// Certificate analysis (if certificate is present)
    pub certificate_analysis: Option<CertificateAnalysis>,
    /// Certificate object (if present and parseable)
    pub certificate: Option<Certificate>,
    /// Error message if certificate couldn't be retrieved or parsed
    pub error: Option<String>,
}

/// YubiKey discovery results
#[derive(Debug, Clone)]
pub struct DiscoveryResults {
    /// All discovered slots
    pub slots: Vec<SlotInfo>,
    /// Slots suitable for code signing (ranked by suitability)
    pub suitable_slots: Vec<PivSlot>,
    /// Recommended slot (best option for code signing)
    pub recommended_slot: Option<PivSlot>,
    /// Total number of certificates found
    pub certificate_count: usize,
    /// Any warnings or issues found during discovery
    pub warnings: Vec<String>,
}

/// Auto-detection service for YubiKey analysis
pub struct AutoDetection;

impl AutoDetection {
    /// Perform comprehensive YubiKey discovery and analysis
    pub fn discover_yubikey_capabilities(
        yubikey_ops: &mut YubiKeyOperations,
    ) -> SigningResult<DiscoveryResults> {
        log::info!("🔍 Starting YubiKey auto-detection and analysis");

        let mut results = DiscoveryResults {
            slots: Vec::new(),
            suitable_slots: Vec::new(),
            recommended_slot: None,
            certificate_count: 0,
            warnings: Vec::new(),
        };

        // Define slots to check (common PIV slots)
        let slots_to_check = [
            PivSlot::new(0x9a).unwrap(), // Authentication
            PivSlot::new(0x9c).unwrap(), // Digital Signature
            PivSlot::new(0x9d).unwrap(), // Key Management
            PivSlot::new(0x9e).unwrap(), // Card Authentication
        ];

        // Check each slot
        for &slot in &slots_to_check {
            let slot_info = Self::analyze_slot(yubikey_ops, slot);
            
            if slot_info.has_certificate {
                results.certificate_count += 1;
                
                if let Some(ref analysis) = slot_info.certificate_analysis {
                    if analysis.is_code_signing_suitable {
                        results.suitable_slots.push(slot);
                        log::info!("✅ Slot {slot} is suitable for code signing");
                    } else {
                        log::warn!("⚠️  Slot {slot} has certificate but not suitable for code signing");
                        for warning in &analysis.warnings {
                            results.warnings.push(format!("Slot {slot}: {warning}"));
                        }
                    }
                }
            }
            
            results.slots.push(slot_info);
        }

        // Determine the best recommended slot
        results.recommended_slot = Self::determine_best_slot(&results.suitable_slots, &results.slots);

        // Add summary warnings
        if results.certificate_count == 0 {
            results.warnings.push("No certificates found in any PIV slot".to_string());
        } else if results.suitable_slots.is_empty() {
            results.warnings.push("Certificates found but none are suitable for code signing".to_string());
        }

        log::info!("🎯 Discovery complete: {} certificates, {} suitable for code signing", 
                  results.certificate_count, results.suitable_slots.len());

        if let Some(recommended) = results.recommended_slot {
            log::info!("🏆 Recommended slot: {recommended}");
        }

        Ok(results)
    }

    /// Analyze a specific PIV slot
    fn analyze_slot(yubikey_ops: &mut YubiKeyOperations, slot: PivSlot) -> SlotInfo {
        log::debug!("Analyzing PIV slot {slot}");

        match yubikey_ops.get_certificate(slot) {
            Ok(certificate) => {
                log::debug!("✅ Certificate found in slot {slot}");
                
                match CertificateValidator::validate_for_code_signing(&certificate) {
                    Ok(analysis) => {
                        SlotInfo {
                            slot,
                            has_certificate: true,
                            certificate_analysis: Some(analysis),
                            certificate: Some(certificate),
                            error: None,
                        }
                    }
                    Err(e) => {
                        log::warn!("❌ Certificate analysis failed for slot {slot}: {e}");
                        SlotInfo {
                            slot,
                            has_certificate: true,
                            certificate_analysis: None,
                            certificate: Some(certificate),
                            error: Some(format!("Certificate analysis failed: {e}")),
                        }
                    }
                }
            }
            Err(e) => {
                log::debug!("❌ No certificate or access error in slot {slot}: {e}");
                SlotInfo {
                    slot,
                    has_certificate: false,
                    certificate_analysis: None,
                    certificate: None,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Determine the best slot from suitable options
    fn determine_best_slot(suitable_slots: &[PivSlot], slot_infos: &[SlotInfo]) -> Option<PivSlot> {
        if suitable_slots.is_empty() {
            return None;
        }

        // Create a mapping of slots to their analysis
        let mut slot_scores: HashMap<PivSlot, f64> = HashMap::new();

        for slot_info in slot_infos {
            if let Some(ref analysis) = slot_info.certificate_analysis {
                if analysis.is_code_signing_suitable {
                    let mut score = 100.0; // Base score

                    // Prefer longer validity periods
                    if analysis.days_until_expiry > 365 {
                        score += 20.0;
                    } else if analysis.days_until_expiry > 90 {
                        score += 10.0;
                    }

                    // Prefer certificates with proper key usage
                    if analysis.has_proper_key_usage {
                        score += 15.0;
                    }

                    // Penalty for warnings
                    score -= analysis.warnings.len() as f64 * 5.0;

                    // Prefer specific slots (Authentication > Digital Signature > others)
                    match slot_info.slot.as_u8() {
                        0x9a => score += 10.0, // Authentication slot (our new default)
                        0x9c => score += 8.0,  // Digital Signature slot
                        0x9d => score += 5.0,  // Key Management
                        0x9e => score += 3.0,  // Card Authentication
                        _ => {}
                    }

                    slot_scores.insert(slot_info.slot, score);
                }
            }
        }

        // Return the slot with the highest score
        slot_scores
            .into_iter()
            .max_by(|(_, score_a), (_, score_b)| score_a.partial_cmp(score_b).unwrap())
            .map(|(slot, _)| slot)
    }

    /// Get detailed slot recommendations with explanations
    pub fn get_slot_recommendations(
        discovery_results: &DiscoveryResults,
    ) -> Vec<SlotRecommendation> {
        let mut recommendations = Vec::new();

        for slot_info in &discovery_results.slots {
            let recommendation = if slot_info.has_certificate {
                if let Some(ref analysis) = slot_info.certificate_analysis {
                    if analysis.is_code_signing_suitable {
                        SlotRecommendation {
                            slot: slot_info.slot,
                            recommendation_level: RecommendationLevel::Recommended,
                            reason: "Certificate is suitable for code signing".to_string(),
                            warnings: analysis.warnings.clone(),
                            details: format!(
                                "Valid for {} days, Subject: {}",
                                analysis.days_until_expiry,
                                analysis.subject
                            ),
                        }
                    } else {
                        SlotRecommendation {
                            slot: slot_info.slot,
                            recommendation_level: RecommendationLevel::NotRecommended,
                            reason: "Certificate is not suitable for code signing".to_string(),
                            warnings: analysis.warnings.clone(),
                            details: format!("Subject: {}", analysis.subject),
                        }
                    }
                } else {
                    SlotRecommendation {
                        slot: slot_info.slot,
                        recommendation_level: RecommendationLevel::Unknown,
                        reason: "Certificate analysis failed".to_string(),
                        warnings: vec![slot_info.error.clone().unwrap_or_default()],
                        details: "Unable to analyze certificate".to_string(),
                    }
                }
            } else {
                SlotRecommendation {
                    slot: slot_info.slot,
                    recommendation_level: RecommendationLevel::NotAvailable,
                    reason: "No certificate in this slot".to_string(),
                    warnings: vec![],
                    details: "Slot is empty or inaccessible".to_string(),
                }
            };

            recommendations.push(recommendation);
        }

        // Sort by recommendation level
        recommendations.sort_by_key(|r| match r.recommendation_level {
            RecommendationLevel::Recommended => 0,
            RecommendationLevel::Caution => 1,
            RecommendationLevel::NotRecommended => 2,
            RecommendationLevel::Unknown => 3,
            RecommendationLevel::NotAvailable => 4,
        });

        recommendations
    }

    /// Find alternative slots if the current one is not suitable
    pub fn find_alternative_slots(
        yubikey_ops: &mut YubiKeyOperations,
        current_slot: PivSlot,
    ) -> SigningResult<Vec<PivSlot>> {
        log::info!("🔍 Finding alternative slots to {current_slot}");

        let discovery = Self::discover_yubikey_capabilities(yubikey_ops)?;
        let mut alternatives: Vec<PivSlot> = discovery
            .suitable_slots
            .into_iter()
            .filter(|&slot| slot != current_slot)
            .collect();

        // Sort alternatives by preference (Authentication > Digital Signature > others)
        alternatives.sort_by_key(|slot| match slot.as_u8() {
            0x9a => 0, // Authentication
            0x9c => 1, // Digital Signature
            0x9d => 2, // Key Management
            0x9e => 3, // Card Authentication
            _ => 4,
        });

        log::info!("Found {} alternative slots", alternatives.len());
        Ok(alternatives)
    }

    /// Quick check if a specific slot is likely to work for code signing
    pub fn quick_slot_check(
        yubikey_ops: &mut YubiKeyOperations,
        slot: PivSlot,
    ) -> SigningResult<bool> {
        log::debug!("Quick check for slot {slot}");

        match yubikey_ops.get_certificate(slot) {
            Ok(certificate) => {
                match CertificateValidator::validate_for_code_signing(&certificate) {
                    Ok(analysis) => Ok(analysis.is_code_signing_suitable),
                    Err(_) => Ok(false), // Analysis failed, assume not suitable
                }
            }
            Err(_) => Ok(false), // No certificate or access error
        }
    }
}

/// Slot recommendation details
#[derive(Debug, Clone)]
pub struct SlotRecommendation {
    /// PIV slot
    pub slot: PivSlot,
    /// Recommendation level
    pub recommendation_level: RecommendationLevel,
    /// Reason for the recommendation
    pub reason: String,
    /// Any warnings or concerns
    pub warnings: Vec<String>,
    /// Additional details about the certificate
    pub details: String,
}

/// Recommendation levels for PIV slots
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecommendationLevel {
    /// Highly recommended for code signing
    Recommended,
    /// Usable but with cautions
    Caution,
    /// Not recommended for code signing
    NotRecommended,
    /// Unknown status (analysis failed)
    Unknown,
    /// No certificate available
    NotAvailable,
}

impl std::fmt::Display for RecommendationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendationLevel::Recommended => write!(f, "✅ Recommended"),
            RecommendationLevel::Caution => write!(f, "⚠️  Use with caution"),
            RecommendationLevel::NotRecommended => write!(f, "❌ Not recommended"),
            RecommendationLevel::Unknown => write!(f, "❓ Unknown"),
            RecommendationLevel::NotAvailable => write!(f, "⭕ Not available"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_slot_info_creation() {
        let slot = PivSlot::new(0x9a).unwrap();
        let slot_info = SlotInfo {
            slot,
            has_certificate: false,
            certificate_analysis: None,
            certificate: None,
            error: Some("No certificate".to_string()),
        };

        assert_eq!(slot_info.slot, slot);
        assert!(!slot_info.has_certificate);
        assert!(slot_info.error.is_some());
    }

    #[test]
    fn test_discovery_results_creation() {
        let results = DiscoveryResults {
            slots: Vec::new(),
            suitable_slots: Vec::new(),
            recommended_slot: None,
            certificate_count: 0,
            warnings: Vec::new(),
        };

        assert_eq!(results.certificate_count, 0);
        assert!(results.slots.is_empty());
        assert!(results.recommended_slot.is_none());
    }

    #[test]
    fn test_recommendation_level_ordering() {
        assert!(RecommendationLevel::Recommended < RecommendationLevel::Caution);
        assert!(RecommendationLevel::Caution < RecommendationLevel::NotRecommended);
        assert!(RecommendationLevel::NotRecommended < RecommendationLevel::Unknown);
        assert!(RecommendationLevel::Unknown < RecommendationLevel::NotAvailable);
    }

    #[test]
    fn test_recommendation_level_display() {
        assert!(RecommendationLevel::Recommended.to_string().contains("Recommended"));
        assert!(RecommendationLevel::Caution.to_string().contains("caution"));
        assert!(RecommendationLevel::NotRecommended.to_string().contains("Not recommended"));
    }
}
