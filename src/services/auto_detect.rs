//! Auto-detection service for `YubiKey` PIV slot configuration.

use crate::adapters::yubikey::ops::YubiKeyOperations;
use crate::domain::types::PivSlot;
use crate::infra::error::SigningResult;
use crate::services::cert_validator::{CertificateAnalysis, CertificateValidator};
use std::collections::HashMap;
use x509_cert::Certificate;

/// Information about a discovered PIV slot
#[derive(Debug, Clone)]
pub struct SlotInfo {
    pub slot: PivSlot,
    pub has_certificate: bool,
    pub certificate_analysis: Option<CertificateAnalysis>,
    pub certificate: Option<Certificate>,
    pub error: Option<String>,
}

/// `YubiKey` discovery results
#[derive(Debug, Clone)]
pub struct DiscoveryResults {
    pub slots: Vec<SlotInfo>,
    pub suitable_slots: Vec<PivSlot>,
    pub recommended_slot: Option<PivSlot>,
    pub certificate_count: usize,
    pub warnings: Vec<String>,
}

/// Auto-detection service for `YubiKey` analysis
pub struct AutoDetection;

impl AutoDetection {
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

        let slots_to_check = [
            PivSlot::new(0x9a).unwrap(),
            PivSlot::new(0x9c).unwrap(),
            PivSlot::new(0x9d).unwrap(),
            PivSlot::new(0x9e).unwrap(),
        ];

        for &slot in &slots_to_check {
            let slot_info = Self::analyze_slot(yubikey_ops, slot);

            if slot_info.has_certificate {
                results.certificate_count += 1;

                if let Some(ref analysis) = slot_info.certificate_analysis {
                    if analysis.is_code_signing_suitable {
                        results.suitable_slots.push(slot);
                        log::info!("✅ Slot {slot} is suitable for code signing");
                    } else {
                        log::warn!(
                            "⚠️  Slot {slot} has certificate but not suitable for code signing"
                        );
                        for warning in &analysis.warnings {
                            results.warnings.push(format!("Slot {slot}: {warning}"));
                        }
                    }
                }
            }

            results.slots.push(slot_info);
        }

        results.recommended_slot =
            Self::determine_best_slot(&results.suitable_slots, &results.slots);

        if results.certificate_count == 0 {
            results
                .warnings
                .push("No certificates found in any PIV slot".to_string());
        } else if results.suitable_slots.is_empty() {
            results
                .warnings
                .push("Certificates found but none are suitable for code signing".to_string());
        }

        log::info!(
            "🎯 Discovery complete: {} certificates, {} suitable for code signing",
            results.certificate_count,
            results.suitable_slots.len()
        );

        if let Some(recommended) = results.recommended_slot {
            log::info!("🏆 Recommended slot: {recommended}");
        }

        Ok(results)
    }

    fn analyze_slot(yubikey_ops: &mut YubiKeyOperations, slot: PivSlot) -> SlotInfo {
        log::debug!("Analyzing PIV slot {slot}");

        match yubikey_ops.get_certificate(slot) {
            Ok(certificate) => {
                log::debug!("✅ Certificate found in slot {slot}");

                match CertificateValidator::validate_for_code_signing(&certificate) {
                    Ok(analysis) => SlotInfo {
                        slot,
                        has_certificate: true,
                        certificate_analysis: Some(analysis),
                        certificate: Some(certificate),
                        error: None,
                    },
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

    fn determine_best_slot(suitable_slots: &[PivSlot], slot_infos: &[SlotInfo]) -> Option<PivSlot> {
        if suitable_slots.is_empty() {
            return None;
        }

        let mut slot_scores: HashMap<PivSlot, f64> = HashMap::new();

        for slot_info in slot_infos {
            if let Some(ref analysis) = slot_info.certificate_analysis {
                if analysis.is_code_signing_suitable {
                    let mut score = 100.0;

                    if analysis.days_until_expiry > 365 {
                        score += 20.0;
                    } else if analysis.days_until_expiry > 90 {
                        score += 10.0;
                    }

                    if analysis.has_proper_key_usage {
                        score += 15.0;
                    }

                    score -= analysis.warnings.len() as f64 * 5.0;

                    match slot_info.slot.as_u8() {
                        0x9a => score += 10.0,
                        0x9c => score += 8.0,
                        0x9d => score += 5.0,
                        0x9e => score += 3.0,
                        _ => {}
                    }

                    slot_scores.insert(slot_info.slot, score);
                }
            }
        }

        slot_scores
            .into_iter()
            .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
            .map(|(slot, _)| slot)
    }

    #[must_use]
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
                                analysis.days_until_expiry, analysis.subject
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

        recommendations.sort_by_key(|r| match r.recommendation_level {
            RecommendationLevel::Recommended => 0,
            RecommendationLevel::Caution => 1,
            RecommendationLevel::NotRecommended => 2,
            RecommendationLevel::Unknown => 3,
            RecommendationLevel::NotAvailable => 4,
        });

        recommendations
    }

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

        alternatives.sort_by_key(|slot| match slot.as_u8() {
            0x9a => 0,
            0x9c => 1,
            0x9d => 2,
            0x9e => 3,
            _ => 4,
        });

        log::info!("Found {} alternative slots", alternatives.len());
        Ok(alternatives)
    }

    pub fn quick_slot_check(
        yubikey_ops: &mut YubiKeyOperations,
        slot: PivSlot,
    ) -> SigningResult<bool> {
        log::debug!("Quick check for slot {slot}");

        match yubikey_ops.get_certificate(slot) {
            Ok(certificate) => {
                match CertificateValidator::validate_for_code_signing(&certificate) {
                    Ok(analysis) => Ok(analysis.is_code_signing_suitable),
                    Err(_) => Ok(false),
                }
            }
            Err(_) => Ok(false),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SlotRecommendation {
    pub slot: PivSlot,
    pub recommendation_level: RecommendationLevel,
    pub reason: String,
    pub warnings: Vec<String>,
    pub details: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecommendationLevel {
    Recommended,
    Caution,
    NotRecommended,
    Unknown,
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
        assert!(RecommendationLevel::Recommended
            .to_string()
            .contains("Recommended"));
        assert!(RecommendationLevel::Caution.to_string().contains("caution"));
        assert!(RecommendationLevel::NotRecommended
            .to_string()
            .contains("Not recommended"));
    }
}
