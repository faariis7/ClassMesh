use std::collections::HashSet;
use std::fmt;

pub const WIFI_FANOUT_EVIDENCE_VERSION: u16 = 1;
pub const WIFI_FANOUT_SCALE_POINTS: &[usize] = &[5, 10, 20, 30];
pub const MAX_BENCHMARK_LABEL_LEN: usize = 64;
pub const MAX_BENCHMARK_DURATION_SECONDS: u32 = 6 * 60 * 60;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiFanoutBenchmarkPlan {
    pub schema_version: u16,
    pub run_id: String,
    pub strategy_label: String,
    pub receiver_ids: Vec<String>,
    pub duration_seconds: u32,
    pub weak_receiver_probe: Option<String>,
}

impl WifiFanoutBenchmarkPlan {
    pub fn validate(&self) -> Result<(), WifiFanoutBenchmarkPlanError> {
        if self.schema_version != WIFI_FANOUT_EVIDENCE_VERSION {
            return Err(WifiFanoutBenchmarkPlanError::UnsupportedVersion(
                self.schema_version,
            ));
        }
        validate_label("run_id", &self.run_id)?;
        validate_label("strategy_label", &self.strategy_label)?;

        if !WIFI_FANOUT_SCALE_POINTS.contains(&self.receiver_ids.len()) {
            return Err(WifiFanoutBenchmarkPlanError::UnsupportedReceiverCount(
                self.receiver_ids.len(),
            ));
        }
        if self.duration_seconds == 0 || self.duration_seconds > MAX_BENCHMARK_DURATION_SECONDS {
            return Err(WifiFanoutBenchmarkPlanError::InvalidDurationSeconds(
                self.duration_seconds,
            ));
        }

        let mut seen = HashSet::with_capacity(self.receiver_ids.len());
        for receiver_id in &self.receiver_ids {
            validate_label("receiver_id", receiver_id)?;
            if !seen.insert(receiver_id.as_str()) {
                return Err(WifiFanoutBenchmarkPlanError::DuplicateReceiverId(
                    receiver_id.clone(),
                ));
            }
        }

        if let Some(receiver_id) = &self.weak_receiver_probe {
            validate_label("weak_receiver_probe", receiver_id)?;
            if !seen.contains(receiver_id.as_str()) {
                return Err(WifiFanoutBenchmarkPlanError::UnknownWeakReceiver(
                    receiver_id.clone(),
                ));
            }
        }

        Ok(())
    }
}

fn validate_label(field: &'static str, value: &str) -> Result<(), WifiFanoutBenchmarkPlanError> {
    if value.is_empty()
        || value.len() > MAX_BENCHMARK_LABEL_LEN
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(WifiFanoutBenchmarkPlanError::InvalidLabel {
            field,
            value: value.to_owned(),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WifiFanoutBenchmarkPlanError {
    UnsupportedVersion(u16),
    InvalidLabel { field: &'static str, value: String },
    UnsupportedReceiverCount(usize),
    InvalidDurationSeconds(u32),
    DuplicateReceiverId(String),
    UnknownWeakReceiver(String),
}

impl fmt::Display for WifiFanoutBenchmarkPlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(
                    formatter,
                    "unsupported Wi-Fi benchmark schema version {version}"
                )
            }
            Self::InvalidLabel { field, value } => {
                write!(formatter, "invalid {field} label {value:?}")
            }
            Self::UnsupportedReceiverCount(count) => write!(
                formatter,
                "unsupported receiver count {count}; expected one of 5, 10, 20, 30"
            ),
            Self::InvalidDurationSeconds(seconds) => write!(
                formatter,
                "invalid benchmark duration {seconds}s; expected 1..={MAX_BENCHMARK_DURATION_SECONDS}"
            ),
            Self::DuplicateReceiverId(receiver_id) => {
                write!(formatter, "duplicate receiver id {receiver_id:?}")
            }
            Self::UnknownWeakReceiver(receiver_id) => {
                write!(
                    formatter,
                    "weak receiver {receiver_id:?} is not in the receiver set"
                )
            }
        }
    }
}

impl std::error::Error for WifiFanoutBenchmarkPlanError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(receiver_count: usize) -> WifiFanoutBenchmarkPlan {
        WifiFanoutBenchmarkPlan {
            schema_version: WIFI_FANOUT_EVIDENCE_VERSION,
            run_id: "wifi-5-direct-001".to_owned(),
            strategy_label: "direct-unicast".to_owned(),
            receiver_ids: (1..=receiver_count)
                .map(|index| format!("student-{index:02}"))
                .collect(),
            duration_seconds: 60,
            weak_receiver_probe: Some("student-01".to_owned()),
        }
    }

    #[test]
    fn accepts_supported_scale_points() {
        for receiver_count in WIFI_FANOUT_SCALE_POINTS {
            assert!(plan(*receiver_count).validate().is_ok());
        }
    }

    #[test]
    fn rejects_non_scale_receiver_count() {
        assert_eq!(
            plan(6).validate(),
            Err(WifiFanoutBenchmarkPlanError::UnsupportedReceiverCount(6))
        );
    }

    #[test]
    fn rejects_duplicate_receiver_identity() {
        let mut plan = plan(5);
        plan.receiver_ids[4] = plan.receiver_ids[0].clone();
        assert!(matches!(
            plan.validate(),
            Err(WifiFanoutBenchmarkPlanError::DuplicateReceiverId(_))
        ));
    }

    #[test]
    fn rejects_weak_receiver_outside_exact_set() {
        let mut plan = plan(5);
        plan.weak_receiver_probe = Some("student-99".to_owned());
        assert_eq!(
            plan.validate(),
            Err(WifiFanoutBenchmarkPlanError::UnknownWeakReceiver(
                "student-99".to_owned()
            ))
        );
    }

    #[test]
    fn labels_are_bounded_and_path_safe() {
        let mut plan = plan(5);
        plan.strategy_label = "direct/unicast".to_owned();
        assert!(matches!(
            plan.validate(),
            Err(WifiFanoutBenchmarkPlanError::InvalidLabel {
                field: "strategy_label",
                ..
            })
        ));
    }

    #[test]
    fn version_and_duration_fail_closed() {
        let mut wrong_version = plan(5);
        wrong_version.schema_version = WIFI_FANOUT_EVIDENCE_VERSION + 1;
        assert_eq!(
            wrong_version.validate(),
            Err(WifiFanoutBenchmarkPlanError::UnsupportedVersion(2))
        );

        let mut no_duration = plan(5);
        no_duration.duration_seconds = 0;
        assert_eq!(
            no_duration.validate(),
            Err(WifiFanoutBenchmarkPlanError::InvalidDurationSeconds(0))
        );
    }
}
