use crate::control_wire::{PresentationStart, PresentationStop};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresentationControlError {
    InvalidPresentationId,
    InvalidStreamId,
    StreamIdOutOfRange,
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
