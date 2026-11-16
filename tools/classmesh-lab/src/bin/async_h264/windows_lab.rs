use std::time::{Duration, Instant};

use classmesh_codec_win::d3d11::create_default_video_device;
use classmesh_codec_win::mf::MfPlatform;
use classmesh_codec_win::mf_decoder::{
    AsyncDecoderEvents, AsyncDecoderPoll, AsyncDecoderSubmit, DecodedGpuFrame, MfAsyncH264Decoder,
    MfDecoderActivation, enumerate_h264_decoders_for_qualification,
};
use serde_json::{Value, json};
use windows::Win32::Foundation::LUID;
use windows::Win32::Graphics::DXCore::{
    DXCoreCreateAdapterFactory, DriverVersion, IDXCoreAdapter, IDXCoreAdapterFactory,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_DECODER_PROFILE_H264_VLD_FGT, D3D11_DECODER_PROFILE_H264_VLD_NOFGT,
    D3D11_DECODER_PROFILE_H264_VLD_WITHFMOASO_NOFGT, D3D11_TEXTURE2D_DESC,
    D3D11_VIDEO_DECODER_DESC, ID3D11Device, ID3D11VideoDevice,
};
use windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT_NV12;
use windows::Win32::Graphics::Dxgi::{DXGI_ADAPTER_FLAG_SOFTWARE, IDXGIAdapter1, IDXGIDevice};
use windows::core::{IUnknown, Interface};

use super::fixture::{AccessUnit, Fixture};
use super::{Failure, complete};

#[path = "presentation.rs"]
mod presentation;
use presentation::Presentation;

const SIZES: [(u32, u32); 2] = [(640, 480), (1280, 720)];
const POLL_INTERVAL: Duration = Duration::from_millis(2);
const START_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_TIMEOUT: Duration = Duration::from_secs(30);

trait At<T> {
    fn at(self, stage: &'static str) -> Result<T, Failure>;
}

impl<T> At<T> for windows::core::Result<T> {
    fn at(self, stage: &'static str) -> Result<T, Failure> {
        self.map_err(|error| Failure {
            stage,
            detail: error.message(),
            hresult: Some(format!("0x{:08X}", error.code().0 as u32)),
        })
    }
}

pub(super) fn run(
    fixtures: Option<[&Fixture; 2]>,
    present: bool,
    report: &mut Value,
) -> Result<(), Failure> {
    let platform = MfPlatform::startup().at("media_foundation_startup")?;
    let registered = enumerate_h264_decoders_for_qualification(None).at("enumerate_h264")?;
    report["registered_transforms"] = json!(inspect(registered).0);
    complete(report, "enumerate_h264");

    let device = create_default_video_device().at("d3d11_create_video_device")?;
    let luid = describe_device(&device, report)?;
    complete(report, "d3d11_video_device");

    let candidates = enumerate_h264_decoders_for_qualification(Some(luid))
        .at("enumerate_adapter_hardware_h264")?;
    let (inventory, eligible) = inspect(candidates);
    report["adapter_transforms"] = json!(inventory);
    complete(report, "enumerate_adapter_hardware_h264");
    let decode_capable = probe_dxva(&device, report)?;
    if fixtures.is_none() {
        return Ok(());
    }
    if !decode_capable {
        return Err(Failure::new(
            "d3d11_h264_nv12",
            "no H.264 VLD/NV12 configuration for both fixture sizes",
        ));
    }
    complete(report, "d3d11_h264_nv12");
    let [first, second] = fixtures.expect("run has two fixtures").map(Fixture::units);
    let fixture = [&first[..], &second[..]];

    let mut decoder = select_decoder(&platform, &device, luid, &eligible, report)?;
    complete(report, "activate_async_d3d11_nv12");
    let result = submit_before_stop(&mut decoder, &first[0]);
    report["interrupted_generation"] = json!({
        "accepted": result.is_ok(),
        "timestamp_100ns": 10_000,
        "events": decoder.events(),
    });
    let stopped = decoder.stop().at("stop_in_flight");
    result?;
    stopped?;
    complete(report, "stop_in_flight");

    let clsid = report["selected_transform"]["clsid"]
        .as_str()
        .expect("selected CLSID")
        .to_owned();
    let mut decoder = reopen(&platform, &device, luid, &clsid)?;
    complete(report, "restart_fresh_generation");
    let interframe = first
        .iter()
        .find(|unit| !unit.idr)
        .expect("fixture contains an interframe");
    let recovery = decoder
        .submit_access_unit(interframe.bytes, 1_000_000, false)
        .at("keyframe_recovery")?;
    if recovery != AsyncDecoderSubmit::WaitingForKeyframe {
        return Err(Failure::new(
            "keyframe_recovery",
            "fresh generation admitted an interframe before an IDR",
        ));
    }
    complete(report, "reject_interframe_after_restart");
    run_generation(decoder, &device, fixture, 2_000_000, None, report, "decode")?;

    if present {
        let mut presentation = Presentation::new(&device)?;
        let decoder = reopen(&platform, &device, luid, &clsid)?;
        run_generation(
            decoder,
            &device,
            fixture,
            30_000_000,
            Some(&mut presentation),
            report,
            "present",
        )?;
        presentation.verify(report)?;
        complete(report, "present_changing_nonblank_frames");
    }
    Ok(())
}

fn inspect(candidates: Vec<MfDecoderActivation>) -> (Vec<Value>, Vec<String>) {
    let mut inventory = Vec::new();
    let mut eligible = Vec::new();
    for candidate in candidates {
        let mut entry = json!({ "name": candidate.name(), "clsid": candidate.clsid() });
        match candidate
            .inspect_for_qualification()
            .at("inspect_transform")
        {
            Ok(caps) => {
                if caps.asynchronous
                    && caps.d3d11_aware
                    && caps.event_generator
                    && caps.shutdown
                    && entry["clsid"] != "unknown"
                {
                    eligible.push(entry["clsid"].as_str().expect("CLSID string").to_owned());
                }
                entry["capabilities"] = json!(caps);
            }
            Err(error) => {
                entry["activation_error"] =
                    json!({ "detail": error.detail, "hresult": error.hresult })
            }
        }
        inventory.push(entry);
    }
    (inventory, eligible)
}

fn describe_device(device: &ID3D11Device, report: &mut Value) -> Result<LUID, Failure> {
    let dxgi: IDXGIDevice = device.cast().at("dxgi_device")?;
    let adapter: IDXGIAdapter1 = unsafe { dxgi.GetAdapter() }
        .and_then(|adapter| adapter.cast())
        .at("dxgi_adapter")?;
    let desc = unsafe { adapter.GetDesc1() }.at("dxgi_adapter_description")?;
    let name = String::from_utf16_lossy(&desc.Description);
    let luid = desc.AdapterLuid;
    let software = desc.Flags & DXGI_ADAPTER_FLAG_SOFTWARE.0 as u32 != 0;
    report["adapter"] = json!({
        "name": name.trim_end_matches('\0'),
        "luid": format!("{:08X}:{:08X}", luid.HighPart as u32, luid.LowPart),
        "vendor_id": desc.VendorId, "device_id": desc.DeviceId,
        "subsystem_id": desc.SubSysId, "revision": desc.Revision,
        "software": software,
    });
    if software {
        return Err(Failure::new(
            "dxgi_hardware_adapter",
            "the selected DXGI adapter is software",
        ));
    }
    let factory: IDXCoreAdapterFactory =
        unsafe { DXCoreCreateAdapterFactory() }.at("dxcore_factory")?;
    let adapter: IDXCoreAdapter =
        unsafe { factory.GetAdapterByLuid(&luid) }.at("dxcore_adapter_by_luid")?;
    let mut version = 0_u64;
    unsafe {
        adapter.GetProperty(
            DriverVersion,
            size_of::<u64>(),
            (&mut version as *mut u64).cast(),
        )
    }
    .at("dxcore_driver_version")?;
    report["adapter"]["driver_version"] = json!(format!(
        "{}.{}.{}.{}",
        version >> 48,
        (version >> 32) & 0xffff,
        (version >> 16) & 0xffff,
        version & 0xffff
    ));
    Ok(luid)
}

fn probe_dxva(device: &ID3D11Device, report: &mut Value) -> Result<bool, Failure> {
    let video: ID3D11VideoDevice = device.cast().at("d3d11_video_interface")?;
    let mut profiles = Vec::new();
    let mut supported = [false; 2];
    for index in 0..unsafe { video.GetVideoDecoderProfileCount() } {
        let profile = unsafe { video.GetVideoDecoderProfile(index) }.at("d3d11_decoder_profile")?;
        if ![
            D3D11_DECODER_PROFILE_H264_VLD_NOFGT,
            D3D11_DECODER_PROFILE_H264_VLD_FGT,
            D3D11_DECODER_PROFILE_H264_VLD_WITHFMOASO_NOFGT,
        ]
        .contains(&profile)
        {
            continue;
        }
        let nv12 = unsafe { video.CheckVideoDecoderFormat(&profile, DXGI_FORMAT_NV12) }
            .at("d3d11_check_decoder_nv12")?
            .as_bool();
        let mut configurations = Vec::new();
        for (index, (width, height)) in SIZES.into_iter().enumerate() {
            if nv12 {
                let desc = D3D11_VIDEO_DECODER_DESC {
                    Guid: profile,
                    SampleWidth: width,
                    SampleHeight: height,
                    OutputFormat: DXGI_FORMAT_NV12,
                };
                match unsafe { video.GetVideoDecoderConfigCount(&desc) }.at("d3d11_decoder_config_count") {
                    Ok(count) => {
                        supported[index] |= count != 0;
                        configurations.push(json!({ "size": [width, height], "count": count }));
                    }
                    Err(error) => configurations.push(json!({ "size": [width, height], "hresult": error.hresult, "detail": error.detail })),
                }
            }
        }
        profiles.push(json!({ "profile": format!("{profile:?}"), "nv12": nv12, "configurations": configurations }));
    }
    report["d3d11_h264_profiles"] = json!(profiles);
    Ok(supported.into_iter().all(|value| value))
}

fn select_decoder<'a>(
    platform: &'a MfPlatform,
    device: &ID3D11Device,
    luid: LUID,
    eligible: &[String],
    report: &mut Value,
) -> Result<MfAsyncH264Decoder<'a>, Failure> {
    let candidates =
        enumerate_h264_decoders_for_qualification(Some(luid)).at("enumerate_for_activation")?;
    report["activation_attempts"] = json!([]);
    let mut failure = Failure::new(
        "select_async_transform",
        "no adapter-scoped H.264 transform met the async and D3D11 requirements",
    );
    for candidate in candidates {
        if !eligible.iter().any(|clsid| clsid == candidate.clsid()) {
            continue;
        }
        let identity = json!({ "name": candidate.name(), "clsid": candidate.clsid() });
        match open(platform, device, candidate).at("activate_async_d3d11_nv12") {
            Ok(decoder) => {
                report["selected_transform"] = identity;
                return Ok(decoder);
            }
            Err(error) => {
                report["activation_attempts"]
                    .as_array_mut()
                    .expect("attempt array")
                    .push(json!({
                        "transform": identity, "hresult": error.hresult, "detail": error.detail,
                    }));
                failure = error;
            }
        }
    }
    Err(failure)
}

fn reopen<'a>(
    platform: &'a MfPlatform,
    device: &ID3D11Device,
    luid: LUID,
    clsid: &str,
) -> Result<MfAsyncH264Decoder<'a>, Failure> {
    let candidate = enumerate_h264_decoders_for_qualification(Some(luid))
        .at("restart_enumeration")?
        .into_iter()
        .find(|candidate| candidate.clsid() == clsid)
        .ok_or_else(|| Failure::new("restart_select_transform", "selected CLSID disappeared"))?;
    open(platform, device, candidate).at("restart_activation")
}

fn open<'a>(
    platform: &'a MfPlatform,
    device: &ID3D11Device,
    candidate: MfDecoderActivation,
) -> windows::core::Result<MfAsyncH264Decoder<'a>> {
    MfAsyncH264Decoder::new_for_qualification_at_size(
        platform, candidate, device, SIZES[0].0, SIZES[0].1,
    )
}

fn submit_before_stop(
    decoder: &mut MfAsyncH264Decoder<'_>,
    unit: &AccessUnit<'_>,
) -> Result<(), Failure> {
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        match decoder
            .submit_access_unit(unit.bytes, 1_000, unit.idr)
            .at("submit_before_stop")?
        {
            AsyncDecoderSubmit::Accepted => return Ok(()),
            AsyncDecoderSubmit::Backpressured => {}
            AsyncDecoderSubmit::WaitingForKeyframe => break,
        }
        if !matches!(
            decoder.poll().at("poll_before_stop")?,
            AsyncDecoderPoll::Pending
        ) {
            return Err(Failure::new(
                "poll_before_stop",
                "decoder produced output before accepting input",
            ));
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    Err(Failure::new(
        "need_input_before_stop",
        "no input credit for the initial IDR",
    ))
}

#[derive(Default)]
struct Playback {
    submitted: usize,
    decoded: usize,
    draining: bool,
    events: AsyncDecoderEvents,
    last_first_size_change_count: u64,
    surfaces: [Vec<Value>; 2],
}

impl Playback {
    fn describe(&self) -> Value {
        json!({
            "submitted": self.submitted,
            "decoded": self.decoded,
            "drain_requested": self.draining,
            "events": self.events,
            "observed_surfaces_by_fixture": self.surfaces,
        })
    }
}

fn run_generation(
    mut decoder: MfAsyncH264Decoder<'_>,
    device: &ID3D11Device,
    fixtures: [&[AccessUnit<'_>]; 2],
    start_us: u64,
    presentation: Option<&mut Presentation>,
    report: &mut Value,
    label: &'static str,
) -> Result<(), Failure> {
    let mut playback = Playback::default();
    let result = play(
        &mut decoder,
        device,
        fixtures,
        start_us,
        presentation,
        &mut playback,
    );
    playback.events = decoder.events();
    report[label] = playback.describe();
    let stopped = decoder.stop().at("retire_drained_transform");
    result?;
    complete(
        report,
        if label == "decode" {
            "decode_and_drain"
        } else {
            "presentation_decode_and_drain"
        },
    );
    stopped?;
    complete(
        report,
        if label == "decode" {
            "retire_decoder"
        } else {
            "retire_presentation_decoder"
        },
    );
    Ok(())
}

fn play(
    decoder: &mut MfAsyncH264Decoder<'_>,
    device: &ID3D11Device,
    fixtures: [&[AccessUnit<'_>]; 2],
    start_us: u64,
    mut presentation: Option<&mut Presentation>,
    playback: &mut Playback,
) -> Result<(), Failure> {
    let deadline = Instant::now() + STREAM_TIMEOUT;
    let first_count = fixtures[0].len();
    let total = first_count + fixtures[1].len();
    let mut inputs = fixtures.into_iter().flatten();
    let mut next = inputs.next();
    while Instant::now() < deadline {
        if let Some(presenter) = presentation.as_deref_mut() {
            presenter.pump()?;
        }
        let mut progress = false;
        if let Some(unit) = next {
            let pts = timestamp(start_us, playback.submitted);
            match decoder
                .submit_access_unit(unit.bytes, pts, unit.idr)
                .at("submit_access_unit")?
            {
                AsyncDecoderSubmit::Accepted => {
                    playback.submitted += 1;
                    next = inputs.next();
                    progress = true;
                }
                AsyncDecoderSubmit::Backpressured => {}
                AsyncDecoderSubmit::WaitingForKeyframe => {
                    return Err(Failure::new(
                        "submit_idr",
                        "decoder rejected the fixture IDR",
                    ));
                }
            }
        }
        if next.is_none() && !playback.draining {
            decoder.begin_drain().at("begin_drain")?;
            playback.draining = true;
        }

        match decoder.poll().at(if playback.draining {
            "poll_drain"
        } else {
            "poll_stream"
        })? {
            AsyncDecoderPoll::Pending => {}
            AsyncDecoderPoll::Frame(frame) => {
                let phase = usize::from(playback.decoded >= first_count);
                let expected = (timestamp(start_us, playback.decoded) * 10) as i64;
                if playback.decoded >= playback.submitted
                    || frame.timestamp_100ns() != Some(expected)
                {
                    return Err(Failure::new(
                        "output_timestamp",
                        format!(
                            "expected {expected} (100 ns), got {:?}",
                            frame.timestamp_100ns()
                        ),
                    ));
                }
                let surface = verify_surface(frame, device, SIZES[phase])?;
                if !playback.surfaces[phase].contains(&surface) {
                    playback.surfaces[phase].push(surface);
                }
                if let Some(presenter) = presentation.as_deref_mut() {
                    presenter.frame(frame, phase)?;
                }
                playback.decoded += 1;
                progress = true;
                let changes = decoder.events().stream_changes;
                if phase == 0 {
                    playback.last_first_size_change_count = changes;
                } else if changes <= playback.last_first_size_change_count {
                    return Err(Failure::new(
                        "midstream_nv12_renegotiation",
                        "second size appeared without a native stream-change renegotiation",
                    ));
                }
            }
            AsyncDecoderPoll::Drained => {
                let events = decoder.events();
                if playback.decoded != total
                    || events.drain_complete != 1
                    || events.need_input == 0
                    || events.have_output < total as u64
                {
                    return Err(Failure::new(
                        "drain_evidence",
                        format!(
                            "expected all {total} frames and native NeedInput/HaveOutput/DrainComplete, decoded {}",
                            playback.decoded
                        ),
                    ));
                }
                if decoder
                    .submit_access_unit(&[0], timestamp(start_us, total), true)
                    .is_ok()
                {
                    return Err(Failure::new(
                        "drained_admission",
                        "drained decoder admitted new input",
                    ));
                }
                return Ok(());
            }
        }
        if !progress {
            std::thread::sleep(POLL_INTERVAL);
        }
    }
    Err(Failure::new(
        "playback_deadline",
        "timed out waiting for native decoder progress",
    ))
}

fn timestamp(start_us: u64, index: usize) -> u64 {
    start_us + index as u64 * 1_000_000 / 30
}

fn verify_surface(
    frame: &DecodedGpuFrame,
    device: &ID3D11Device,
    (width, height): (u32, u32),
) -> Result<Value, Failure> {
    let owner = unsafe { frame.texture().GetDevice() }.at("texture_device")?;
    if owner.cast::<IUnknown>().at("texture_device_identity")?
        != device.cast::<IUnknown>().at("expected_device_identity")?
    {
        return Err(Failure::new(
            "texture_device_identity",
            "output belongs to a different D3D11 device",
        ));
    }
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { frame.texture().GetDesc(&mut desc) };
    if desc.Format != DXGI_FORMAT_NV12
        || desc.SampleDesc.Count != 1
        || !(width..=width + 63).contains(&desc.Width)
        || !(height..=height + 63).contains(&desc.Height)
    {
        return Err(Failure::new(
            "nv12_surface_geometry",
            format!(
                "expected {width}x{height} NV12 with at most 63 pixels of driver padding per axis; got {}x{}, format {}, samples {}",
                desc.Width, desc.Height, desc.Format.0, desc.SampleDesc.Count
            ),
        ));
    }
    let index = unsafe { frame.dxgi_buffer().GetSubresourceIndex() }.at("dxgi_subresource")?;
    if index != frame.subresource_index() || desc.MipLevels != 1 || index >= desc.ArraySize {
        return Err(Failure::new(
            "dxgi_subresource",
            format!(
                "invalid NV12 subresource {index} ({} mips, {} slices)",
                desc.MipLevels, desc.ArraySize
            ),
        ));
    }
    Ok(
        json!({ "format": "NV12", "width": desc.Width, "height": desc.Height, "array_size": desc.ArraySize, "array_slice": index }),
    )
}
