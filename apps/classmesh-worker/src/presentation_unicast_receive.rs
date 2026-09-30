#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use classmesh_windows_runtime::ipc::ServicePresentationUnicastStart;
    use classmesh_windows_runtime::ipc_sensitive::PresentationKeyInstallBinding;

    use super::*;

    fn start(request_id: u64, teacher_source: IpAddr) -> ServicePresentationUnicastStart {
        ServicePresentationUnicastStart {
            control_session_id: 77,
            request_id,
            presentation_id: 55,
            stream_id: 9,
            width: 1920,
            height: 1080,
            fps: 30,
            bitrate_kbps: 6_000,
            port: 49_000,
            teacher_source,
        }
    }

    #[test]
    fn receiver_config_preserves_exact_unicast_binding_for_both_ip_families() {
        for teacher_source in [
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ] {
            let start = start(44, teacher_source);
            let config = receiver_config(start).expect("valid receiver config");
            assert_eq!(config.expected_sender(), start.teacher_source);
            assert_eq!(config.stream_id(), start.stream_id);
            assert_eq!(config.port(), start.port);
            assert_eq!(
                config.local_bind(),
                SocketAddr::new(
                    match start.teacher_source {
                        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                    },
                    start.port,
                )
            );
        }
    }

    #[test]
    fn retry_request_id_does_not_change_unicast_media_configuration() {
        let teacher = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44));
        assert!(same_media_configuration(
            start(44, teacher),
            start(45, teacher)
        ));
    }

    #[test]
    fn changed_unicast_media_binding_requires_runtime_replacement() {
        let current = start(44, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
        for candidate in [
            ServicePresentationUnicastStart {
                presentation_id: 56,
                ..current
            },
            ServicePresentationUnicastStart {
                stream_id: 10,
                ..current
            },
            ServicePresentationUnicastStart {
                port: 49_001,
                ..current
            },
            ServicePresentationUnicastStart {
                teacher_source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45)),
                ..current
            },
        ] {
            assert!(!same_media_configuration(current, candidate));
        }
    }

    #[test]
    fn runtime_binds_reserved_loopback_port_and_adopts_request_only_retry() {
        let reservation = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .expect("reserve loopback port");
        let port = reservation.local_addr().expect("reserved address").port();
        drop(reservation);

        let first = ServicePresentationUnicastStart {
            port,
            teacher_source: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ..start(44, IpAddr::V4(Ipv4Addr::LOCALHOST))
        };
        let mut runtime =
            WorkerPresentationUnicastRuntime::start(first).expect("unicast runtime starts");
        assert_eq!(runtime.binding(), first);
        assert!(!runtime.failed());

        let retry = ServicePresentationUnicastStart {
            request_id: 45,
            ..first
        };
        assert!(runtime.adopt_retry(retry));
        assert_eq!(runtime.binding().request_id, 45);
    }

    #[test]
    fn key_binding_requires_exact_control_presentation_and_stream() {
        let start = start(44, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 44)));
        let exact = PresentationKeyInstallBinding {
            control_session_id: start.control_session_id,
            request_id: 99,
            presentation_id: start.presentation_id,
            stream_id: start.stream_id,
            epoch: 3,
        };
        assert!(start_matches_key_binding(start, exact));

        for key in [
            PresentationKeyInstallBinding {
                control_session_id: exact.control_session_id + 1,
                ..exact
            },
            PresentationKeyInstallBinding {
                presentation_id: exact.presentation_id + 1,
                ..exact
            },
            PresentationKeyInstallBinding {
                stream_id: exact.stream_id + 1,
                ..exact
            },
        ] {
            assert!(!start_matches_key_binding(start, key));
        }
    }
}
