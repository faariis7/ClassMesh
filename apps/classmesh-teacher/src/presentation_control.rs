//! Correlation for one presentation on the existing authenticated Teacher session.
use classmesh_protocol::control_wire::{PresentationState, control_envelope::Payload};

use crate::presentation_view::PresentationBindingView;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pending {
    Start(u64),
    Key(u64),
    Offer(u64),
    Stop(u64),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PresentationReply {
    Started,
    KeyInstalled,
    TransportReady,
    Stopped,
    Rejected,
}

pub(crate) struct PresentationControl {
    pub(crate) binding: PresentationBindingView,
    pending: Pending,
}

impl PresentationControl {
    pub(crate) fn new(binding: PresentationBindingView, request: u64) -> Self {
        Self {
            binding,
            pending: Pending::Start(request),
        }
    }

    pub(crate) fn wait_for_key(&mut self, request: u64) {
        self.pending = Pending::Key(request);
    }

    pub(crate) fn wait_for_offer(&mut self, request: u64) {
        self.pending = Pending::Offer(request);
    }

    pub(crate) fn wait_for_stop(&mut self, request: u64) {
        self.pending = Pending::Stop(request);
    }

    pub(crate) fn waiting(&self) -> bool {
        self.pending != Pending::None
    }

    pub(crate) fn can_stop(&self, binding: PresentationBindingView) -> bool {
        binding == self.binding && !matches!(self.pending, Pending::Stop(_))
    }

    pub(crate) fn accept(&mut self, request: u64, payload: &Payload) -> Option<PresentationReply> {
        let binding = self.binding;
        let expected_stream = u64::from(binding.stream_id);
        let reply = match (self.pending, payload) {
            (Pending::Start(id), Payload::PresentationStatus(s))
                if id == request && s.presentation_id == binding.presentation_id =>
            {
                match PresentationState::try_from(s.state).ok()? {
                    PresentationState::Starting if s.stream_id == expected_stream => {
                        PresentationReply::Started
                    }
                    PresentationState::Rejected
                        if s.stream_id == expected_stream || s.stream_id == 0 =>
                    {
                        PresentationReply::Rejected
                    }
                    _ => return None,
                }
            }
            (Pending::Key(id), Payload::PresentationKeyAck(ack))
                if id == request
                    && ack.presentation_id == binding.presentation_id
                    && ack.stream_id == expected_stream
                    && ack.epoch == binding.epoch =>
            {
                PresentationReply::KeyInstalled
            }
            (Pending::Offer(id), Payload::StreamAnswer(answer))
                if id == request && answer.stream_id == expected_stream =>
            {
                if answer.accepted {
                    PresentationReply::TransportReady
                } else {
                    PresentationReply::Rejected
                }
            }
            (Pending::Stop(id), Payload::PresentationStatus(s))
                if id == request && s.presentation_id == binding.presentation_id =>
            {
                match PresentationState::try_from(s.state).ok()? {
                    PresentationState::Stopped if s.stream_id == expected_stream => {
                        PresentationReply::Stopped
                    }
                    PresentationState::Rejected
                        if s.stream_id == expected_stream || s.stream_id == 0 =>
                    {
                        PresentationReply::Rejected
                    }
                    _ => return None,
                }
            }
            _ => return None,
        };
        self.pending = Pending::None;
        Some(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presentation_view::PresentationBindingView;
    use classmesh_protocol::control_wire::{PresentationStatus, StreamAnswer};

    fn binding() -> PresentationBindingView {
        PresentationBindingView {
            presentation_id: 11,
            stream_id: 12,
            epoch: 1,
        }
    }

    fn accepted() -> Payload {
        Payload::StreamAnswer(StreamAnswer {
            stream_id: 12,
            accepted: true,
            ..Default::default()
        })
    }

    #[test]
    fn installed_presentation_requires_exact_remote_start_key_and_transport() {
        let mut p = PresentationControl::new(binding(), 7);
        assert!(p.waiting());
        assert_eq!(p.accept(7, &accepted()), None);
        let started = Payload::PresentationStatus(PresentationStatus {
            presentation_id: 11,
            stream_id: 12,
            state: PresentationState::Starting as i32,
            diagnostic: String::new(),
        });
        assert_eq!(p.accept(8, &started), None);
        assert_eq!(p.accept(7, &started), Some(PresentationReply::Started));
        p.wait_for_key(8);
        let mut ack = classmesh_protocol::control_wire::PresentationKeyAck {
            presentation_id: 11,
            stream_id: 12,
            epoch: 2,
        };
        assert_eq!(p.accept(8, &Payload::PresentationKeyAck(ack)), None);
        ack.epoch = 1;
        assert_eq!(
            p.accept(8, &Payload::PresentationKeyAck(ack)),
            Some(PresentationReply::KeyInstalled)
        );
        p.wait_for_offer(9);
        assert_eq!(
            p.accept(9, &accepted()),
            Some(PresentationReply::TransportReady)
        );
        assert_eq!(p.accept(9, &accepted()), None);
        assert!(!p.waiting());
    }

    #[test]
    fn installed_presentation_rejects_stale_stop_and_distinguishes_remote_refusal() {
        let mut p = PresentationControl::new(binding(), 7);
        assert!(!p.can_stop(PresentationBindingView {
            epoch: 2,
            ..binding()
        }));
        assert!(p.can_stop(binding()));
        p.wait_for_stop(8);
        let mut stopped = PresentationStatus {
            presentation_id: 10,
            stream_id: 12,
            state: PresentationState::Stopped as i32,
            diagnostic: String::new(),
        };
        assert_eq!(
            p.accept(8, &Payload::PresentationStatus(stopped.clone())),
            None
        );
        stopped.presentation_id = 11;
        assert_eq!(
            p.accept(8, &Payload::PresentationStatus(stopped)),
            Some(PresentationReply::Stopped)
        );

        p.wait_for_offer(9);
        let mut answer = StreamAnswer {
            stream_id: 12,
            ..Default::default()
        };
        assert_eq!(
            p.accept(9, &Payload::StreamAnswer(answer.clone())),
            Some(PresentationReply::Rejected)
        );
        answer.accepted = true;
        assert_eq!(p.accept(9, &Payload::StreamAnswer(answer)), None);
    }
}
