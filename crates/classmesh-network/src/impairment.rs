#![forbid(unsafe_code)]

use core::fmt;

const BASIS_POINTS_PER_100_PERCENT: u16 = 10_000;

/// Deterministic packet impairment settings used only by benchmarks and qualification tools.
///
/// Percentages are represented in basis points so tests never depend on floating-point random
/// comparisons. For example, 300 means 3.00%.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImpairmentConfig {
    pub loss_basis_points: u16,
    pub reorder_basis_points: u16,
    pub jitter_max_us: u64,
    pub reorder_extra_delay_us: u64,
    pub seed: u64,
}

impl Default for ImpairmentConfig {
    fn default() -> Self {
        Self {
            loss_basis_points: 0,
            reorder_basis_points: 0,
            jitter_max_us: 0,
            reorder_extra_delay_us: 0,
            seed: 1,
        }
    }
}

impl ImpairmentConfig {
    pub fn validate(self) -> Result<Self, ImpairmentConfigError> {
        if self.loss_basis_points > BASIS_POINTS_PER_100_PERCENT {
            return Err(ImpairmentConfigError::LossOutOfRange);
        }
        if self.reorder_basis_points > BASIS_POINTS_PER_100_PERCENT {
            return Err(ImpairmentConfigError::ReorderOutOfRange);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpairmentConfigError {
    LossOutOfRange,
    ReorderOutOfRange,
}

impl fmt::Display for ImpairmentConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LossOutOfRange => {
                formatter.write_str("loss percentage must be between 0% and 100%")
            }
            Self::ReorderOutOfRange => {
                formatter.write_str("reorder percentage must be between 0% and 100%")
            }
        }
    }
}

impl std::error::Error for ImpairmentConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImpairmentDecision {
    Drop,
    DeliverAt { due_us: u64, reordered: bool },
}

/// Small reproducible impairment engine for ClassMesh media qualification.
///
/// This is intentionally not cryptographic randomness. Given the same configuration and packet
/// order it produces exactly the same loss/jitter/reorder decisions, which makes regressions
/// repeatable in CI and on physical LAN tests.
#[derive(Debug, Clone)]
pub struct ImpairmentEngine {
    config: ImpairmentConfig,
    rng: XorShift64,
    packets_seen: u64,
    packets_dropped: u64,
    packets_reordered: u64,
}

impl ImpairmentEngine {
    pub fn new(config: ImpairmentConfig) -> Result<Self, ImpairmentConfigError> {
        let config = config.validate()?;
        Ok(Self {
            rng: XorShift64::new(config.seed),
            config,
            packets_seen: 0,
            packets_dropped: 0,
            packets_reordered: 0,
        })
    }

    #[must_use]
    pub const fn config(&self) -> ImpairmentConfig {
        self.config
    }

    #[must_use]
    pub const fn packets_seen(&self) -> u64 {
        self.packets_seen
    }

    #[must_use]
    pub const fn packets_dropped(&self) -> u64 {
        self.packets_dropped
    }

    #[must_use]
    pub const fn packets_reordered(&self) -> u64 {
        self.packets_reordered
    }

    /// Chooses loss and delivery timing for one packet at `now_us`.
    ///
    /// Jitter is a deterministic uniform delay in `[0, jitter_max_us]`. A packet selected for
    /// reordering receives an additional configured delay; later packets can therefore overtake it
    /// naturally in the proxy's bounded scheduler.
    pub fn plan(&mut self, now_us: u64) -> ImpairmentDecision {
        self.packets_seen = self.packets_seen.saturating_add(1);
        if self.draw_basis_points() < self.config.loss_basis_points {
            self.packets_dropped = self.packets_dropped.saturating_add(1);
            return ImpairmentDecision::Drop;
        }

        let jitter_us = self.draw_delay(self.config.jitter_max_us);
        let reordered = self.draw_basis_points() < self.config.reorder_basis_points;
        let reorder_delay_us = if reordered {
            self.packets_reordered = self.packets_reordered.saturating_add(1);
            self.config.reorder_extra_delay_us
        } else {
            0
        };
        ImpairmentDecision::DeliverAt {
            due_us: now_us
                .saturating_add(jitter_us)
                .saturating_add(reorder_delay_us),
            reordered,
        }
    }

    fn draw_basis_points(&mut self) -> u16 {
        let value = self.rng.next_u64() % u64::from(BASIS_POINTS_PER_100_PERCENT);
        u16::try_from(value).expect("modulo 10,000 always fits u16")
    }

    fn draw_delay(&mut self, max_us: u64) -> u64 {
        if max_us == 0 {
            return 0;
        }
        self.rng.next_u64() % max_us.saturating_add(1)
    }
}

#[derive(Debug, Clone, Copy)]
struct XorShift64 {
    state: u64,
}

impl XorShift64 {
    const fn new(seed: u64) -> Self {
        // Xorshift has an all-zero absorbing state. Map zero to a fixed non-zero seed while keeping
        // every other user-supplied seed exactly reproducible.
        Self {
            state: if seed == 0 {
                0x9E37_79B9_7F4A_7C15
            } else {
                seed
            },
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_produces_same_decisions() {
        let config = ImpairmentConfig {
            loss_basis_points: 300,
            reorder_basis_points: 1_000,
            jitter_max_us: 5_000,
            reorder_extra_delay_us: 20_000,
            seed: 42,
        };
        let mut first = ImpairmentEngine::new(config).unwrap();
        let mut second = ImpairmentEngine::new(config).unwrap();
        for packet in 0..1_000_u64 {
            assert_eq!(first.plan(packet * 100), second.plan(packet * 100));
        }
    }

    #[test]
    fn one_hundred_percent_loss_drops_every_packet() {
        let mut engine = ImpairmentEngine::new(ImpairmentConfig {
            loss_basis_points: 10_000,
            ..ImpairmentConfig::default()
        })
        .unwrap();
        for packet in 0..100_u64 {
            assert_eq!(engine.plan(packet), ImpairmentDecision::Drop);
        }
        assert_eq!(engine.packets_dropped(), 100);
    }

    #[test]
    fn zero_impairment_delivers_immediately() {
        let mut engine = ImpairmentEngine::new(ImpairmentConfig::default()).unwrap();
        assert_eq!(
            engine.plan(123_456),
            ImpairmentDecision::DeliverAt {
                due_us: 123_456,
                reordered: false,
            }
        );
    }

    #[test]
    fn delay_never_exceeds_configured_bounds() {
        let config = ImpairmentConfig {
            reorder_basis_points: 10_000,
            jitter_max_us: 7_000,
            reorder_extra_delay_us: 11_000,
            seed: 9,
            ..ImpairmentConfig::default()
        };
        let mut engine = ImpairmentEngine::new(config).unwrap();
        for now_us in 0..1_000_u64 {
            let ImpairmentDecision::DeliverAt { due_us, reordered } = engine.plan(now_us) else {
                panic!("loss is disabled");
            };
            assert!(reordered);
            assert!(due_us >= now_us + 11_000);
            assert!(due_us <= now_us + 18_000);
        }
    }

    #[test]
    fn invalid_percentages_are_rejected() {
        assert_eq!(
            ImpairmentConfig {
                loss_basis_points: 10_001,
                ..ImpairmentConfig::default()
            }
            .validate(),
            Err(ImpairmentConfigError::LossOutOfRange)
        );
        assert_eq!(
            ImpairmentConfig {
                reorder_basis_points: 10_001,
                ..ImpairmentConfig::default()
            }
            .validate(),
            Err(ImpairmentConfigError::ReorderOutOfRange)
        );
    }
}
