use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RenditionTier {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenditionProfile {
    pub tier: RenditionTier,
    pub width: u16,
    pub height: u16,
    pub fps: u8,
    pub bitrate_kbps: u32,
}

impl RenditionProfile {
    #[must_use]
    pub const fn high() -> Self {
        Self {
            tier: RenditionTier::High,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 5_000,
        }
    }

    #[must_use]
    pub const fn medium() -> Self {
        Self {
            tier: RenditionTier::Medium,
            width: 1280,
            height: 720,
            fps: 30,
            bitrate_kbps: 2_500,
        }
    }

    #[must_use]
    pub const fn low() -> Self {
        Self {
            tier: RenditionTier::Low,
            width: 854,
            height: 480,
            fps: 20,
            bitrate_kbps: 900,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RenditionPlannerConfig {
    pub max_renditions: u8,
    /// Do not spend another encoder/rendition for one isolated weak receiver unless policy decides
    /// it is worth it. This keeps GPU cost bounded.
    pub min_receivers_for_extra_rendition: usize,
}

impl Default for RenditionPlannerConfig {
    fn default() -> Self {
        Self {
            max_renditions: 3,
            min_receivers_for_extra_rendition: 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReceiverDemand {
    pub tier: RenditionTier,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenditionPlan {
    pub profiles: Vec<RenditionProfile>,
}

/// Builds a small, deterministic set of presentation renditions.
///
/// Simulcast is deliberately optional. The default is one high-quality classroom stream; extra
/// renditions are added only when enough receivers need them and encoder budget allows it.
#[must_use]
pub fn plan_renditions(
    config: RenditionPlannerConfig,
    demands: &[ReceiverDemand],
) -> RenditionPlan {
    let max = usize::from(config.max_renditions.max(1));
    let mut profiles = vec![RenditionProfile::high()];
    if max == 1 || demands.is_empty() {
        return RenditionPlan { profiles };
    }

    let low_count = demands
        .iter()
        .filter(|demand| demand.tier == RenditionTier::Low)
        .count();
    let medium_count = demands
        .iter()
        .filter(|demand| demand.tier == RenditionTier::Medium)
        .count();

    let mut requested = BTreeSet::new();
    if medium_count >= config.min_receivers_for_extra_rendition {
        requested.insert(RenditionTier::Medium);
    }
    if low_count >= config.min_receivers_for_extra_rendition {
        requested.insert(RenditionTier::Low);
    }

    // Prefer a lower rendition before medium when the encoder budget is extremely tight because a
    // low rendition is the most likely to rescue a constrained Wi-Fi receiver.
    for tier in [RenditionTier::Low, RenditionTier::Medium] {
        if profiles.len() >= max || !requested.contains(&tier) {
            continue;
        }
        profiles.push(match tier {
            RenditionTier::High => RenditionProfile::high(),
            RenditionTier::Medium => RenditionProfile::medium(),
            RenditionTier::Low => RenditionProfile::low(),
        });
    }

    RenditionPlan { profiles }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_weak_receiver_does_not_force_second_encoder() {
        let plan = plan_renditions(
            RenditionPlannerConfig::default(),
            &[ReceiverDemand {
                tier: RenditionTier::Low,
            }],
        );
        assert_eq!(plan.profiles, vec![RenditionProfile::high()]);
    }

    #[test]
    fn multiple_weak_receivers_can_justify_low_rendition() {
        let demands = vec![
            ReceiverDemand {
                tier: RenditionTier::Low,
            };
            5
        ];
        let plan = plan_renditions(RenditionPlannerConfig::default(), &demands);
        assert_eq!(plan.profiles.len(), 2);
        assert!(plan.profiles.contains(&RenditionProfile::low()));
    }

    #[test]
    fn rendition_count_never_exceeds_gpu_budget() {
        let demands = [
            ReceiverDemand {
                tier: RenditionTier::Low,
            },
            ReceiverDemand {
                tier: RenditionTier::Low,
            },
            ReceiverDemand {
                tier: RenditionTier::Low,
            },
            ReceiverDemand {
                tier: RenditionTier::Medium,
            },
            ReceiverDemand {
                tier: RenditionTier::Medium,
            },
            ReceiverDemand {
                tier: RenditionTier::Medium,
            },
        ];
        let plan = plan_renditions(
            RenditionPlannerConfig {
                max_renditions: 2,
                min_receivers_for_extra_rendition: 3,
            },
            &demands,
        );
        assert_eq!(plan.profiles.len(), 2);
    }
}
