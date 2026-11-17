use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::E_NOTIMPL;
use windows::Win32::Graphics::Direct3D11::{ID3D11Device, ID3D11Multithread, ID3D11VideoDevice};
use windows::Win32::Media::MediaFoundation::{
    IMFMediaEvent, IMFMediaEventGenerator, IMFMediaType, IMFShutdown, IMFTransform, MEError,
    METransformDrainComplete, METransformHaveOutput, METransformNeedInput,
    MF_E_NO_EVENTS_AVAILABLE, MF_E_TRANSFORM_STREAM_CHANGE, MF_EVENT_FLAG_NO_WAIT,
    MF_EVENT_MFT_INPUT_STREAM_ID, MF_MT_FRAME_SIZE, MF_TRANSFORM_ASYNC, MF_TRANSFORM_ASYNC_UNLOCK,
    MFSampleExtension_CleanPoint, MFSampleExtension_Discontinuity, MFT_MESSAGE_COMMAND_DRAIN,
    MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_TYPE,
};
use windows::core::{Interface, Result};

use super::{
    DecodedGpuFrame, DecoderActivationGuard, DecoderOutput, MfDecoderActivation, StreamState,
    checked_sample_time, classmesh_decoder_error, configure_decoder, configure_nv12_output,
    create_compressed_sample_at, create_h264_input_type, prefer_device_failure, process_one_output,
    require_decoder_owned_output,
};
use crate::mf::{MfDxgiDeviceManager, MfPlatform};

const MAX_EVENTS_PER_POLL: usize = 32;
const MAX_INPUT_CREDITS: usize = 64;
const MAX_PENDING_TIMESTAMPS: usize = 64;
const DRAIN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, PartialEq, Eq)]
pub enum AsyncDecoderSubmit {
    Accepted,
    Backpressured,
    WaitingForKeyframe,
}

#[derive(Debug)]
pub enum AsyncDecoderPoll<Frame> {
    Frame(Frame),
    Pending,
    Drained,
}

/// Successful native events handled by a single decoder generation.
#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct AsyncDecoderEvents {
    pub need_input: u64,
    pub have_output: u64,
    pub drain_complete: u64,
    pub stream_changes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Streaming,
    Draining(Instant),
    Drained,
    Retired,
}

struct AsyncEvents {
    phase: Phase,
    input_stream: u32,
    input_credits: usize,
    pending: BTreeSet<i64>,
    waiting_for_keyframe: bool,
    events: AsyncDecoderEvents,
}

impl AsyncEvents {
    fn new(input_stream: u32) -> Self {
        Self {
            phase: Phase::Streaming,
            input_stream,
            input_credits: 0,
            pending: BTreeSet::new(),
            waiting_for_keyframe: true,
            events: AsyncDecoderEvents::default(),
        }
    }

    fn retire(&mut self) {
        self.phase = Phase::Retired;
        self.input_credits = 0;
        self.pending.clear();
    }

    fn submit(
        &mut self,
        timestamp_us: u64,
        keyframe: bool,
        send: impl FnOnce(i64, bool) -> Result<()>,
    ) -> Result<AsyncDecoderSubmit> {
        if self.phase != Phase::Streaming {
            return Err(classmesh_decoder_error(
                "async H.264 decoder is not accepting input",
            ));
        }
        if self.waiting_for_keyframe && !keyframe {
            return Ok(AsyncDecoderSubmit::WaitingForKeyframe);
        }
        if self.input_credits == 0 || self.pending.len() == MAX_PENDING_TIMESTAMPS {
            return Ok(AsyncDecoderSubmit::Backpressured);
        }
        let timestamp = checked_sample_time(timestamp_us)?;
        if self.pending.contains(&timestamp) {
            return Err(classmesh_decoder_error(
                "async H.264 input reused a pending timestamp",
            ));
        }
        if let Err(error) = send(timestamp, self.waiting_for_keyframe) {
            self.retire();
            return Err(error);
        }
        self.pending.insert(timestamp);
        self.input_credits -= 1;
        self.waiting_for_keyframe = false;
        Ok(AsyncDecoderSubmit::Accepted)
    }

    fn match_output_time(&mut self, timestamp: Option<i64>) -> Result<()> {
        if !timestamp.is_some_and(|timestamp| self.pending.remove(&timestamp)) {
            return Err(classmesh_decoder_error(
                "async H.264 output has no matching input timestamp in this stream",
            ));
        }
        Ok(())
    }

    fn poll(
        &mut self,
        mut next: impl FnMut() -> Result<IMFMediaEvent>,
        mut output: impl FnMut() -> Result<DecoderOutput>,
    ) -> Result<AsyncDecoderPoll<DecodedGpuFrame>> {
        const NEED_INPUT: u32 = METransformNeedInput.0 as u32;
        const HAVE_OUTPUT: u32 = METransformHaveOutput.0 as u32;
        const DRAIN_COMPLETE: u32 = METransformDrainComplete.0 as u32;
        const ERROR: u32 = MEError.0 as u32;

        for _ in 0..MAX_EVENTS_PER_POLL {
            match self.phase {
                Phase::Retired => {
                    return Err(classmesh_decoder_error("async H.264 decoder retired"));
                }
                Phase::Drained => return Ok(AsyncDecoderPoll::Drained),
                Phase::Draining(deadline) if Instant::now() >= deadline => {
                    return Err(classmesh_decoder_error(
                        "incomplete async H.264 drain: no DrainComplete before the deadline",
                    ));
                }
                Phase::Streaming | Phase::Draining(_) => {}
            }
            let event = match next() {
                Ok(event) => event,
                Err(error) if error.code() == MF_E_NO_EVENTS_AVAILABLE => {
                    return Ok(AsyncDecoderPoll::Pending);
                }
                Err(error) => return Err(error),
            };
            unsafe { event.GetStatus()? }.ok()?;
            match unsafe { event.GetType()? } {
                NEED_INPUT => {
                    validate_event_stream(&event, self.input_stream)?;
                    self.events.need_input += 1;
                    // NeedInput events may already have been queued when EOS was sent.
                    if self.phase == Phase::Streaming {
                        if self.input_credits == MAX_INPUT_CREDITS {
                            return Err(classmesh_decoder_error(
                                "async H.264 input-credit budget exhausted",
                            ));
                        }
                        self.input_credits += 1;
                    }
                }
                HAVE_OUTPUT => {
                    self.events.have_output += 1;
                    match output()? {
                        DecoderOutput::Frame(frame) => {
                            self.match_output_time(frame.timestamp_100ns())?;
                            return Ok(AsyncDecoderPoll::Frame(frame));
                        }
                        DecoderOutput::Progress => {}
                        DecoderOutput::NeedInput => {
                            return Err(classmesh_decoder_error(
                                "async H.264 returned NeedInput after a HaveOutput event",
                            ));
                        }
                    }
                }
                DRAIN_COMPLETE => {
                    validate_event_stream(&event, self.input_stream)?;
                    if !matches!(self.phase, Phase::Draining(_)) {
                        return Err(classmesh_decoder_error(
                            "async H.264 delivered DrainComplete outside an active drain",
                        ));
                    }
                    self.pending.clear();
                    self.events.drain_complete += 1;
                    self.phase = Phase::Drained;
                    return Ok(AsyncDecoderPoll::Drained);
                }
                ERROR => {
                    return Err(classmesh_decoder_error(
                        "async H.264 decoder reported MEError",
                    ));
                }
                _ => {}
            }
        }
        Ok(AsyncDecoderPoll::Pending)
    }
}

/// Event-driven H.264 decoder for Windows adapter qualification.
///
/// The Student Worker keeps rejecting async-only MFTs until a physical x64 adapter
/// passes decoder and presenter qualification. This backend requires nonblocking
/// `IMFMediaEventGenerator::GetEvent(MF_EVENT_FLAG_NO_WAIT)`. One instance belongs
/// to one generation. On reset, Stop, or device loss, discard this instance and
/// any returned frame before creating a replacement.
pub struct MfAsyncH264Decoder<'platform> {
    returned_frame: Option<DecodedGpuFrame>,
    transform: IMFTransform,
    events: IMFMediaEventGenerator,
    activation: DecoderActivationGuard,
    device: ID3D11Device,
    _device_manager: MfDxgiDeviceManager,
    _platform: &'platform MfPlatform,
    output_stream: u32,
    stream: StreamState,
    state: AsyncEvents,
}

impl<'platform> MfAsyncH264Decoder<'platform> {
    /// Opens an async, video-capable MFT for a controlled qualification run.
    /// Enables multithread protection on the device's immediate context before
    /// sharing it with the transform.
    ///
    /// # Errors
    /// Returns a Windows error when a required interface, stream, media type,
    /// or nonblocking event source is unavailable.
    pub fn new_for_qualification(
        platform: &'platform MfPlatform,
        activation: MfDecoderActivation,
        device: &ID3D11Device,
    ) -> Result<Self> {
        Self::open(platform, activation, device, &create_h264_input_type()?)
    }

    /// Opens the decoder with the fixture's initial coded size. The MFT
    /// still negotiates output and any later size change from the bitstream.
    ///
    /// # Errors
    /// Returns a Windows error when setup, negotiation or startup fails.
    pub fn new_for_qualification_at_size(
        platform: &'platform MfPlatform,
        activation: MfDecoderActivation,
        device: &ID3D11Device,
        width: u32,
        height: u32,
    ) -> Result<Self> {
        let input_type = create_h264_input_type()?;
        unsafe {
            input_type.SetUINT64(
                &MF_MT_FRAME_SIZE,
                (u64::from(width) << 32) | u64::from(height),
            )?
        };
        Self::open(platform, activation, device, &input_type)
    }

    fn open(
        platform: &'platform MfPlatform,
        activation: MfDecoderActivation,
        device: &ID3D11Device,
        input_type: &IMFMediaType,
    ) -> Result<Self> {
        device.cast::<ID3D11VideoDevice>()?;
        let context = unsafe { device.GetImmediateContext()? };
        let threading: ID3D11Multithread = context.cast()?;
        unsafe {
            let _ = threading.SetMultithreadProtected(true);
            if !threading.GetMultithreadProtected().as_bool() {
                return Err(classmesh_decoder_error(
                    "async H.264 requires a protected D3D11 immediate context",
                ));
            }
        }
        let guard = DecoderActivationGuard::new(activation.activation);
        let transform = guard.activate()?;
        let attributes = unsafe { transform.GetAttributes()? };
        if unsafe { attributes.GetUINT32(&MF_TRANSFORM_ASYNC)? } != 1 {
            return Err(classmesh_decoder_error("H.264 decoder is not an async MFT"));
        }
        let events: IMFMediaEventGenerator = transform.cast()?;
        // The activation guard calls ShutdownObject on success and on early exit.
        transform.cast::<IMFShutdown>()?;
        unsafe { attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)? };
        let (input_stream, output_stream) = stream_ids(&transform)?;
        let device_manager = configure_decoder(
            &transform,
            &attributes,
            device,
            (input_stream, output_stream),
            input_type,
        )?;

        let mut decoder = Self {
            returned_frame: None,
            transform,
            events,
            activation: guard,
            device: device.clone(),
            _device_manager: device_manager,
            _platform: platform,
            output_stream,
            stream: StreamState::Stopped,
            state: AsyncEvents::new(input_stream),
        };
        unsafe {
            decoder
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?
        };
        decoder.stream = StreamState::Streaming;
        unsafe {
            decoder
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?
        };
        // Check the native event source before returning an adapter. Preserve events
        // if the transform has already given an input credit at start.
        match decoder.poll()? {
            AsyncDecoderPoll::Pending => Ok(decoder),
            _ => Err(classmesh_decoder_error(
                "async H.264 produced output before receiving input",
            )),
        }
    }

    /// Takes one input credit once the MFT accepts the sample. The caller
    /// retains the access unit on Backpressured. No implicit frame queue exists.
    ///
    /// # Errors
    /// Returns an error for invalid data, a retired stream, or a failed submission.
    pub fn submit_access_unit(
        &mut self,
        access_unit: &[u8],
        timestamp_us: u64,
        keyframe: bool,
    ) -> Result<AsyncDecoderSubmit> {
        if access_unit.is_empty() {
            return Err(classmesh_decoder_error("empty H.264 access unit"));
        }
        let input_stream = self.state.input_stream;
        self.state
            .submit(timestamp_us, keyframe, |timestamp, first| {
                let sample = create_compressed_sample_at(access_unit, timestamp)?;
                if keyframe {
                    unsafe { sample.SetUINT32(&MFSampleExtension_CleanPoint, 1)? };
                }
                if first {
                    unsafe { sample.SetUINT32(&MFSampleExtension_Discontinuity, 1)? };
                }
                unsafe { self.transform.ProcessInput(input_stream, &sample, 0) }
                    .map_err(|error| prefer_device_failure(&self.device, error))
            })
    }

    /// Processes up to 32 queued events without waiting for a new event.
    /// A returned frame is borrowed until the next call. The adapter releases
    /// its sample before requesting another output or stopping the generation.
    ///
    /// # Errors
    /// Returns an event, decoder, device, or drain-timeout error and retires the decoder.
    pub fn poll(&mut self) -> Result<AsyncDecoderPoll<&DecodedGpuFrame>> {
        drop(self.returned_frame.take());
        let mut changes = 0;
        let result = self.state.poll(
            || unsafe { self.events.GetEvent(MF_EVENT_FLAG_NO_WAIT) },
            || match process_one_output(&self.transform, &self.device, self.output_stream) {
                Err(error) if error.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    configure_nv12_output(&self.transform, self.output_stream)?;
                    require_decoder_owned_output(&self.transform, self.output_stream)?;
                    changes += 1;
                    Ok(DecoderOutput::Progress)
                }
                result => result,
            },
        );
        self.state.events.stream_changes += changes;
        match result {
            Ok(AsyncDecoderPoll::Frame(frame)) => {
                Ok(AsyncDecoderPoll::Frame(self.returned_frame.insert(frame)))
            }
            Ok(AsyncDecoderPoll::Pending) => Ok(AsyncDecoderPoll::Pending),
            Ok(AsyncDecoderPoll::Drained) => Ok(AsyncDecoderPoll::Drained),
            Err(error) => {
                self.state.retire();
                Err(prefer_device_failure(&self.device, error))
            }
        }
    }

    /// Counts observed transform events and successful NV12 renegotiations.
    #[must_use]
    pub const fn events(&self) -> AsyncDecoderEvents {
        self.state.events
    }

    /// Closes input. Poll until the transform signals DrainComplete.
    ///
    /// # Errors
    /// Returns an error for a non-streaming adapter or a failed drain request.
    pub fn begin_drain(&mut self) -> Result<()> {
        if self.state.phase != Phase::Streaming {
            return Err(classmesh_decoder_error(
                "cannot drain an inactive async H.264 stream",
            ));
        }
        drop(self.returned_frame.take());
        self.state.input_credits = 0;
        self.state.phase = Phase::Draining(Instant::now() + DRAIN_TIMEOUT);
        let stream = self.state.input_stream;
        if let Err(error) = self
            .stream
            .begin_drain(|message| send_message(&self.transform, stream, message))
        {
            self.state.retire();
            return Err(prefer_device_failure(&self.device, error));
        }
        Ok(())
    }

    /// Flushes pending input/output and shuts down this generation. After a
    /// reset, create a new activation so old events cannot authorize new work.
    ///
    /// # Errors
    /// Returns the first transform cleanup error.
    pub fn stop(mut self) -> Result<()> {
        let end = self.stop_stream();
        end.and(self.activation.shutdown())
    }

    fn stop_stream(&mut self) -> Result<()> {
        self.state.retire();
        drop(self.returned_frame.take());
        let stream = self.state.input_stream;
        self.stream
            .end(|message| send_message(&self.transform, stream, message))
    }
}

impl Drop for MfAsyncH264Decoder<'_> {
    fn drop(&mut self) {
        let _ = self.stop_stream();
    }
}

fn validate_event_stream(event: &IMFMediaEvent, expected: u32) -> Result<()> {
    let stream = unsafe { event.GetUINT32(&MF_EVENT_MFT_INPUT_STREAM_ID)? };
    if stream != expected {
        return Err(classmesh_decoder_error(
            "async H.264 event referenced an unexpected input stream",
        ));
    }
    Ok(())
}

fn stream_ids(transform: &IMFTransform) -> Result<(u32, u32)> {
    let mut input_count = 0;
    let mut output_count = 0;
    unsafe { transform.GetStreamCount(&mut input_count, &mut output_count)? };
    if (input_count, output_count) != (1, 1) {
        return Err(classmesh_decoder_error(
            "async H.264 requires one input and one output stream",
        ));
    }
    let (mut input, mut output) = ([0], [0]);
    match unsafe { transform.GetStreamIDs(&mut input, &mut output) } {
        Ok(()) => Ok((input[0], output[0])),
        Err(error) if error.code() == E_NOTIMPL => Ok((0, 0)),
        Err(error) => Err(error),
    }
}

fn send_message(
    transform: &IMFTransform,
    input_stream: u32,
    message: MFT_MESSAGE_TYPE,
) -> Result<()> {
    let parameter = if matches!(
        message,
        MFT_MESSAGE_NOTIFY_END_OF_STREAM | MFT_MESSAGE_COMMAND_DRAIN
    ) {
        input_stream as usize
    } else {
        0
    };
    unsafe { transform.ProcessMessage(message, parameter) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Media::MediaFoundation::{
        IMFMediaEventQueue, METransformMarker, MF_EVENT_TYPE, MFCreateEventQueue,
        MFCreateMediaEvent,
    };
    use windows::core::{GUID, HRESULT};

    fn queue_event(
        queue: &IMFMediaEventQueue,
        kind: MF_EVENT_TYPE,
        stream: Option<u32>,
        status: HRESULT,
    ) {
        let event =
            unsafe { MFCreateMediaEvent(kind.0 as u32, &GUID::zeroed(), status, None) }.unwrap();
        if let Some(stream) = stream {
            unsafe { event.SetUINT32(&MF_EVENT_MFT_INPUT_STREAM_ID, stream) }.unwrap();
        }
        unsafe { queue.QueueEvent(&event) }.unwrap();
    }

    fn next(queue: &IMFMediaEventQueue) -> Result<IMFMediaEvent> {
        unsafe { queue.GetEvent(MF_EVENT_FLAG_NO_WAIT.0) }
    }

    #[test]
    fn native_need_and_have_events_each_authorize_one_operation() {
        let _platform = MfPlatform::startup().unwrap();
        let queue = unsafe { MFCreateEventQueue() }.unwrap();
        for _ in 0..2 {
            queue_event(&queue, METransformNeedInput, Some(9), HRESULT(0));
        }
        let mut state = AsyncEvents::new(9);
        assert!(matches!(
            state.poll(|| next(&queue), || unreachable!()).unwrap(),
            AsyncDecoderPoll::Pending
        ));
        let mut inputs = 0;
        assert_eq!(
            state.submit(8, false, |_, _| unreachable!()).unwrap(),
            AsyncDecoderSubmit::WaitingForKeyframe
        );
        for time in 8..10 {
            assert_eq!(
                state
                    .submit(time, time == 8, |timestamp, first| {
                        assert_eq!(timestamp, time as i64 * 10);
                        assert_eq!(first, time == 8);
                        inputs += 1;
                        Ok(())
                    })
                    .unwrap(),
                AsyncDecoderSubmit::Accepted
            );
        }
        assert_eq!(
            state.submit(11, false, |_, _| unreachable!()).unwrap(),
            AsyncDecoderSubmit::Backpressured
        );
        queue_event(&queue, METransformHaveOutput, None, HRESULT(0));
        let mut outputs = 0;
        state
            .poll(
                || next(&queue),
                || {
                    outputs += 1;
                    Ok(DecoderOutput::Progress)
                },
            )
            .unwrap();
        assert_eq!((inputs, outputs), (2, 1));
        assert_eq!(state.events.need_input, 2);
        assert_eq!(state.events.have_output, 1);
        assert_eq!(state.events.drain_complete, 0);
        unsafe { queue.Shutdown() }.unwrap();
    }

    #[test]
    fn native_drain_complete_is_required_and_preceded_by_queued_output() {
        let _platform = MfPlatform::startup().unwrap();
        let queue = unsafe { MFCreateEventQueue() }.unwrap();
        let mut state = AsyncEvents::new(7);
        state.phase = Phase::Draining(Instant::now() + DRAIN_TIMEOUT);
        queue_event(&queue, METransformNeedInput, Some(7), HRESULT(0));
        queue_event(&queue, METransformHaveOutput, None, HRESULT(0));
        let mut outputs = 0;
        assert!(matches!(
            state
                .poll(
                    || next(&queue),
                    || {
                        outputs += 1;
                        Ok(DecoderOutput::Progress)
                    }
                )
                .unwrap(),
            AsyncDecoderPoll::Pending
        ));
        assert_eq!(state.input_credits, 0);
        assert_eq!(outputs, 1);
        assert!(state.submit(1, true, |_, _| unreachable!()).is_err());
        queue_event(&queue, METransformDrainComplete, Some(0), HRESULT(0));
        assert!(state.poll(|| next(&queue), || unreachable!()).is_err());
        queue_event(&queue, METransformDrainComplete, Some(7), HRESULT(0));
        assert!(matches!(
            state.poll(|| next(&queue), || unreachable!()).unwrap(),
            AsyncDecoderPoll::Drained
        ));
        assert!(matches!(
            state.poll(|| unreachable!(), || unreachable!()).unwrap(),
            AsyncDecoderPoll::Drained
        ));
        assert_eq!(state.events.drain_complete, 1);
        unsafe { queue.Shutdown() }.unwrap();
    }

    #[test]
    fn event_batches_and_input_credits_have_independent_bounds() {
        let _platform = MfPlatform::startup().unwrap();
        let queue = unsafe { MFCreateEventQueue() }.unwrap();
        for _ in 0..=MAX_EVENTS_PER_POLL {
            queue_event(&queue, METransformMarker, None, HRESULT(0));
        }
        let mut state = AsyncEvents::new(0);
        let mut polls = 0;
        state
            .poll(
                || {
                    polls += 1;
                    next(&queue)
                },
                || unreachable!(),
            )
            .unwrap();
        assert_eq!(polls, MAX_EVENTS_PER_POLL);
        assert_eq!(
            unsafe { next(&queue).unwrap().GetType() }.unwrap(),
            METransformMarker.0 as u32
        );
        state.input_credits = MAX_INPUT_CREDITS;
        queue_event(&queue, METransformNeedInput, Some(0), HRESULT(0));
        assert!(state.poll(|| next(&queue), || unreachable!()).is_err());
        unsafe { queue.Shutdown() }.unwrap();
    }

    #[test]
    fn rejects_bad_event_sequence_and_status() {
        let _platform = MfPlatform::startup().unwrap();
        let queue = unsafe { MFCreateEventQueue() }.unwrap();
        let mut state = AsyncEvents::new(0);
        for stream in [None, Some(1)] {
            queue_event(&queue, METransformNeedInput, stream, HRESULT(0));
            assert!(state.poll(|| next(&queue), || unreachable!()).is_err());
        }
        queue_event(&queue, METransformDrainComplete, Some(0), HRESULT(0));
        assert!(state.poll(|| next(&queue), || unreachable!()).is_err());
        queue_event(&queue, METransformHaveOutput, None, HRESULT(0));
        assert!(
            state
                .poll(|| next(&queue), || Ok(DecoderOutput::NeedInput))
                .is_err()
        );
        queue_event(&queue, METransformHaveOutput, None, E_NOTIMPL);
        let error = state.poll(|| next(&queue), || unreachable!()).unwrap_err();
        assert_eq!(error.code(), E_NOTIMPL);
        unsafe { queue.Shutdown() }.unwrap();
    }

    #[test]
    fn timestamps_and_credits_cannot_cross_retirement() {
        let mut retired = AsyncEvents::new(0);
        retired.input_credits = 3;
        assert!(
            retired
                .submit(u64::MAX, true, |_, _| unreachable!())
                .is_err()
        );
        assert_eq!(retired.input_credits, 3);
        retired.submit(9, true, |_, _| Ok(())).unwrap();
        assert!(retired.submit(9, false, |_, _| unreachable!()).is_err());
        assert!(retired.match_output_time(Some(90)).is_ok());
        assert!(retired.match_output_time(Some(90)).is_err());
        retired.submit(10, false, |_, _| Ok(())).unwrap();
        retired.retire();
        assert!(retired.pending.is_empty());
        assert_eq!(retired.input_credits, 0);
        assert!(retired.poll(|| unreachable!(), || unreachable!()).is_err());
        let mut replacement = AsyncEvents::new(0);
        assert!(replacement.match_output_time(Some(100)).is_err());
        assert_eq!(
            replacement
                .submit(11, false, |_, _| unreachable!())
                .unwrap(),
            AsyncDecoderSubmit::WaitingForKeyframe
        );
    }

    #[test]
    fn full_timestamp_ledger_backpressures_until_a_sample_is_released() {
        let mut state = AsyncEvents::new(0);
        state.input_credits = MAX_PENDING_TIMESTAMPS;
        for time in 0..MAX_PENDING_TIMESTAMPS as u64 {
            assert_eq!(
                state.submit(time, time == 0, |_, _| Ok(())).unwrap(),
                AsyncDecoderSubmit::Accepted
            );
        }
        state.input_credits = 1; // The transform granted a new NeedInput.
        assert_eq!(
            state.submit(100, false, |_, _| unreachable!()).unwrap(),
            AsyncDecoderSubmit::Backpressured
        );
        state.match_output_time(Some(0)).unwrap();
        assert_eq!(
            state.submit(100, false, |_, _| Ok(())).unwrap(),
            AsyncDecoderSubmit::Accepted
        );
        assert_eq!(state.pending.len(), MAX_PENDING_TIMESTAMPS);
    }

    #[test]
    fn failed_submission_and_drain_timeout_end_admission() {
        let mut state = AsyncEvents::new(0);
        state.input_credits = 1;
        assert!(
            state
                .submit(1, true, |_, _| Err(classmesh_decoder_error(
                    "device failed"
                )))
                .is_err()
        );
        assert!(state.submit(2, true, |_, _| unreachable!()).is_err());
        let mut drain = AsyncEvents::new(0);
        drain.phase = Phase::Draining(Instant::now());
        assert!(
            drain
                .poll(|| unreachable!(), || unreachable!())
                .unwrap_err()
                .message()
                .contains("incomplete async H.264 drain")
        );
    }
}
