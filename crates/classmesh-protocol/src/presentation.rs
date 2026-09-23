use crate::control_wire::{PresentationStart, PresentationState, PresentationStatus, PresentationStop};

pub const MAX_PRESENTATION_DIAGNOSTIC_BYTES: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationControlError {
    InvalidPresentationId,
    InvalidStreamId,
    StreamIdOutOfRange,
    InvalidState,
    DiagnosticTooLarge,
}

pub fn validate_start(start: &PresentationStart) -> Result<(), PresentationControlError> {
    if start.presentation_id == 0 {
        return Err(PresentationControlError::InvalidPresentationId);
    }
    if start.stream_id == 0 {
        return Err(PresentationControlError::InvalidStreamId);
    }
    if u32::try_from(start.stream_id).is_err() {
        return Err(PresentationControlError::StreamIdOutOfRange);
    }
    Ok(())
}

pub fn validate_stop(stop: &PresentationStop) -> Result<(), PresentationControlError> {
    if stop.presentation_id == 0 {
        return Err(PresentationControlError::InvalidPresentationId);
    }
    Ok(())
}

pub fn validate_status(status: &PresentationStatus) -> Result<(), PresentationControlError> {
    if status.presentation_id == 0 {
        return Err(PresentationControlError::InvalidPresentationId);
    }
    if status.stream_id == 0 {
        return Err(PresentationControlError::InvalidStreamId);
    }
    if u32::try_from(status.stream_id).is_err() {
        return Err(PresentationControlError::StreamIdOutOfRange);
    }
    let state = PresentationState::try_from(status.state)
        .map_err(|_| PresentationControlError::InvalidState)?;
    if state == PresentationState::Unspecified {
        return Err(PresentationControlError::InvalidState);
    }
    if status.diagnostic.len() > MAX_PRESENTATION_DIAGNOSTIC_BYTES {
        return Err(PresentationControlError::DiagnosticTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_requires_nonzero_ids_and_media_header_stream_range() {
        assert_eq!(
            validate_start(&PresentationStart {
                presentation_id: 0,
                stream_id: 7,
            }),
            Err(PresentationControlError::InvalidPresentationId)
        );
        assert_eq!(
            validate_start(&PresentationStart {
                presentation_id: 9,
                stream_id: 0,
            }),
            Err(PresentationControlError::InvalidStreamId)
        );
        assert_eq!(
            validate_start(&PresentationStart {
                presentation_id: 9,
                stream_id: u64::from(u32::MAX) + 1,
            }),
            Err(PresentationControlError::StreamIdOutOfRange)
        );
        assert_eq!(
            validate_start(&PresentationStart {
                presentation_id: 9,
                stream_id: 7,
            }),
            Ok(())
        );
    }

    #[test]
    fn status_is_bounded_and_requires_known_state() {
        let mut status = PresentationStatus {
            presentation_id: 9,
            stream_id: 7,
            state: PresentationState::Active as i32,
            diagnostic: String::new(),
        };
        assert_eq!(validate_status(&status), Ok(()));

        status.state = PresentationState::Unspecified as i32;
        assert_eq!(
            validate_status(&status),
            Err(PresentationControlError::InvalidState)
        );

        status.state = i32::MAX;
        assert_eq!(
            validate_status(&status),
            Err(PresentationControlError::InvalidState)
        );

        status.state = PresentationState::Rejected as i32;
        status.diagnostic = "x".repeat(MAX_PRESENTATION_DIAGNOSTIC_BYTES + 1);
        assert_eq!(
            validate_status(&status),
            Err(PresentationControlError::DiagnosticTooLarge)
        );
    }

    #[test]
    fn stop_requires_nonzero_presentation_id() {
        assert_eq!(
            validate_stop(&PresentationStop { presentation_id: 0 }),
            Err(PresentationControlError::InvalidPresentationId)
        );
        assert_eq!(
            validate_stop(&PresentationStop { presentation_id: 9 }),
            Ok(())
        );
    }
}
