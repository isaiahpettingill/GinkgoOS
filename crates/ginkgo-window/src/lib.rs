#![no_std]

//! Serializable window protocol types and a transport-independent client state
//! machine.
//!
//! The crate intentionally owns its wire geometry and keeps transport attachment
//! indices out of public events. It supports in-memory transports directly; the
//! syscall-backed channel transport is provided by `ginkgo-userspace`.

extern crate alloc;

mod channel;
mod client;
mod geometry;
mod protocol;

pub use channel::*;
pub use client::*;
pub use geometry::*;
pub use protocol::*;

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use alloc::{collections::VecDeque, string::String, vec, vec::Vec};
    use core::convert::Infallible;
    use std::{cell::Cell, rc::Rc};

    use super::*;

    #[derive(Clone, Default)]
    struct DropCount(Rc<Cell<usize>>);

    impl DropCount {
        fn get(&self) -> usize {
            self.0.get()
        }
    }

    struct MockSurface {
        bytes: Vec<u8>,
        drops: DropCount,
    }

    impl MockSurface {
        fn new(length: usize, fill: u8, drops: DropCount) -> Self {
            Self {
                bytes: vec![fill; length],
                drops,
            }
        }
    }

    impl Drop for MockSurface {
        fn drop(&mut self) {
            self.drops.0.set(self.drops.0.get() + 1);
        }
    }

    impl SharedSurface for MockSurface {
        type Error = Infallible;

        fn len(&self) -> usize {
            self.bytes.len()
        }

        fn bytes_mut(&mut self) -> Result<&mut [u8], Self::Error> {
            Ok(&mut self.bytes)
        }
    }

    #[derive(Default)]
    struct MockTransport {
        sent: Vec<WireRequest>,
        incoming: VecDeque<Received<MockSurface>>,
    }

    impl MockTransport {
        fn push(&mut self, event: WireEvent, surfaces: Vec<MockSurface>) {
            self.incoming.push_back(Received::new(event, surfaces));
        }
    }

    impl Transport for MockTransport {
        type Error = Infallible;
        type Surface = MockSurface;

        fn send(&mut self, request: &WireRequest) -> Result<(), Self::Error> {
            self.sent.push(request.clone());
            Ok(())
        }

        fn receive(&mut self) -> Result<Option<Received<Self::Surface>>, Self::Error> {
            Ok(self.incoming.pop_front())
        }
    }

    fn request_id(value: u64) -> RequestId {
        RequestId::new(value).unwrap()
    }

    fn window_id(value: u64) -> WindowId {
        WindowId::new(value).unwrap()
    }

    fn generation(value: u32) -> Generation {
        Generation::new(value).unwrap()
    }

    fn fractional_scale() -> ScaleFactor {
        ScaleFactor::new(3, 2).unwrap()
    }

    fn configuration(generation_value: u32, buffer_count: u8) -> SurfaceConfiguration {
        SurfaceConfiguration {
            logical_size: Size::new(4, 2),
            pixel_size: Size::new(6, 3),
            stride: 24,
            format: PixelFormat::Xrgb8888,
            scale: fractional_scale(),
            generation: generation(generation_value),
            buffer_count,
        }
    }

    fn configure(
        client: &mut WindowClient<MockTransport>,
        generation_value: u32,
        buffer_count: u8,
        drops: DropCount,
    ) -> Event {
        let config = configuration(generation_value, buffer_count);
        let length = config.required_surface_bytes().unwrap();
        client
            .process_received(Received::new(
                WireEvent::Configured(Configured {
                    window_id: window_id(9),
                    configuration: config,
                    surface_handle_index: 0,
                }),
                vec![MockSurface::new(length, 0, drops)],
            ))
            .unwrap()
    }

    fn connected_client() -> WindowClient<MockTransport> {
        let mut client = WindowClient::new(MockTransport::default());
        let create_id = client.create_window(WindowOptions::default()).unwrap();
        assert_eq!(create_id, request_id(1));
        client.transport_mut().push(
            WireEvent::WindowCreated {
                protocol_version: PROTOCOL_VERSION,
                request_id: create_id,
                window_id: window_id(9),
            },
            Vec::new(),
        );
        let event = client.poll_event().unwrap().unwrap();
        assert!(matches!(event, Event::WindowCreated { .. }));
        client
    }

    #[test]
    fn fractional_scale_normalizes_round_trips_and_rejects_zero() {
        let scale = ScaleFactor::new(6, 4).unwrap();
        assert_eq!(scale, fractional_scale());
        assert_eq!(scale.numerator(), 3);
        assert_eq!(scale.denominator(), 2);
        assert_eq!(scale.scale_size(Size::new(5, 3)), Some(Size::new(8, 5)));
        assert_eq!(ScaleFactor::new(0, 1), Err(ScaleFactorError::ZeroNumerator));
        assert_eq!(
            ScaleFactor::new(1, 0),
            Err(ScaleFactorError::ZeroDenominator)
        );

        let encoded = postcard::to_allocvec(&scale).unwrap();
        let decoded: ScaleFactor = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, fractional_scale());

        let zero_numerator = postcard::to_allocvec(&(0_u32, 1_u32)).unwrap();
        let zero_denominator = postcard::to_allocvec(&(1_u32, 0_u32)).unwrap();
        assert!(postcard::from_bytes::<ScaleFactor>(&zero_numerator).is_err());
        assert!(postcard::from_bytes::<ScaleFactor>(&zero_denominator).is_err());
    }

    #[test]
    fn protocol_pixel_formats_convert_exactly_to_graphics_formats() {
        assert_eq!(
            ginkgo_graphics::PixelFormat::from(PixelFormat::Xrgb8888),
            ginkgo_graphics::PixelFormat::Xrgb8888
        );
        assert_eq!(
            ginkgo_graphics::PixelFormat::from(PixelFormat::Argb8888),
            ginkgo_graphics::PixelFormat::Argb8888
        );
        assert_eq!(PixelFormat::Xrgb8888.minimum_stride(10), Some(40));

        for format in [PixelFormat::Xrgb8888, PixelFormat::Argb8888] {
            let encoded = postcard::to_allocvec(&format).unwrap();
            assert_eq!(
                postcard::from_bytes::<PixelFormat>(&encoded).unwrap(),
                format
            );
        }
        let unknown_format = postcard::to_allocvec(&99_u8).unwrap();
        assert!(postcard::from_bytes::<PixelFormat>(&unknown_format).is_err());
    }

    #[test]
    fn window_options_and_surface_configuration_validate_sizes() {
        let mut options = WindowOptions::default();
        options.preferred_size = Size::new(0, 10);
        assert_eq!(
            options.validate(),
            Err(WindowOptionsError::EmptyPreferredSize)
        );

        options.preferred_size = Size::new(640, 480);
        options.minimum_size = Some(Size::new(800, 600));
        options.maximum_size = Some(Size::new(700, 700));
        assert_eq!(
            options.validate(),
            Err(WindowOptionsError::InvertedConstraints)
        );
        options.maximum_size = Some(Size::new(1000, 800));
        assert_eq!(
            options.validate(),
            Err(WindowOptionsError::PreferredSizeOutsideConstraints)
        );

        let mut config = configuration(1, MIN_BUFFER_SLOTS);
        assert_eq!(config.validate(), Ok(()));
        config.pixel_size = Size::new(6, 4);
        assert_eq!(
            config.validate(),
            Err(ConfigurationError::PixelSizeMismatch)
        );
        config.pixel_size = Size::new(6, 3);
        config.stride = 23;
        assert_eq!(config.validate(), Err(ConfigurationError::StrideTooSmall));
        config.stride = 24;
        config.buffer_count = 1;
        assert_eq!(config.validate(), Err(ConfigurationError::TooFewBuffers));
    }

    #[test]
    fn create_handshake_round_trips_with_protocol_version() {
        let request = WireRequest::CreateWindow {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id(42),
            options: WindowOptions {
                title: String::from("Terminal"),
                preferred_size: Size::new(640, 480),
                minimum_size: Some(Size::new(320, 200)),
                maximum_size: Some(Size::new(1920, 1080)),
                scale_factor: Some(fractional_scale()),
                preferred_formats: vec![PixelFormat::Argb8888, PixelFormat::Xrgb8888],
                resizable: true,
                decorations: true,
                transparent: true,
                fullscreen: false,
            },
        };
        let encoded = postcard::to_allocvec(&request).unwrap();
        let decoded: WireRequest = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, request);

        let response = WireEvent::WindowCreated {
            protocol_version: PROTOCOL_VERSION,
            request_id: request_id(42),
            window_id: window_id(9),
        };
        let encoded = postcard::to_allocvec(&response).unwrap();
        let decoded: WireEvent = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn rejects_a_mismatched_handshake_version() {
        let mut client = WindowClient::new(MockTransport::default());
        let create_id = client.create_window(WindowOptions::default()).unwrap();
        assert!(matches!(
            client.transport().sent.first(),
            Some(WireRequest::CreateWindow {
                protocol_version: PROTOCOL_VERSION,
                request_id,
                ..
            }) if *request_id == create_id
        ));

        let received_version = PROTOCOL_VERSION + 1;
        assert!(matches!(
            client.process_received(Received::new(
                WireEvent::WindowCreated {
                    protocol_version: received_version,
                    request_id: create_id,
                    window_id: window_id(9),
                },
                Vec::new(),
            )),
            Err(ClientError::Protocol(
                ProtocolError::ProtocolVersionMismatch {
                    expected: PROTOCOL_VERSION,
                    received,
                }
            )) if received == received_version
        ));
        assert_eq!(client.window_id(), None);
        assert_eq!(
            client.create_window(WindowOptions::default()).unwrap(),
            request_id(2)
        );
    }

    #[test]
    fn allocates_monotonic_request_ids_and_validates_create_reply() {
        let mut client = WindowClient::new(MockTransport::default());
        let create_id = client.create_window(WindowOptions::default()).unwrap();
        assert_eq!(create_id, request_id(1));
        assert!(matches!(
            client.create_window(WindowOptions::default()),
            Err(ClientError::Protocol(ProtocolError::CreateAlreadyPending))
        ));
        assert!(matches!(
            client.process_received(Received::new(
                WireEvent::WindowCreated {
                    protocol_version: PROTOCOL_VERSION,
                    request_id: request_id(2),
                    window_id: window_id(9),
                },
                Vec::new(),
            )),
            Err(ClientError::Protocol(
                ProtocolError::UnexpectedCreateReply { .. }
            ))
        ));
    }

    #[test]
    fn size_and_fullscreen_requests_do_not_mutate_active_configuration() {
        let mut client = connected_client();
        configure(&mut client, 1, 2, DropCount::default());
        let active = client.active_configuration().unwrap();

        assert_eq!(
            client.request_size(Size::new(900, 700)).unwrap(),
            request_id(2)
        );
        assert_eq!(
            client.set_minimum_size(Some(Size::new(320, 200))).unwrap(),
            request_id(3)
        );
        assert_eq!(
            client
                .set_maximum_size(Some(Size::new(1920, 1080)))
                .unwrap(),
            request_id(4)
        );
        assert_eq!(client.set_fullscreen(true).unwrap(), request_id(5));
        assert_eq!(client.toggle_fullscreen().unwrap(), request_id(6));
        assert_eq!(client.active_configuration(), Some(active));

        assert_eq!(
            &client.transport().sent[1..],
            &[
                WireRequest::RequestSize {
                    request_id: request_id(2),
                    window_id: window_id(9),
                    preferred_size: Size::new(900, 700),
                },
                WireRequest::SetMinimumSize {
                    request_id: request_id(3),
                    window_id: window_id(9),
                    minimum_size: Some(Size::new(320, 200)),
                },
                WireRequest::SetMaximumSize {
                    request_id: request_id(4),
                    window_id: window_id(9),
                    maximum_size: Some(Size::new(1920, 1080)),
                },
                WireRequest::SetFullscreen {
                    request_id: request_id(5),
                    window_id: window_id(9),
                    fullscreen: true,
                },
                WireRequest::ToggleFullscreen {
                    request_id: request_id(6),
                    window_id: window_id(9),
                },
            ]
        );

        let sent_count = client.transport().sent.len();
        assert!(matches!(
            client.request_size(Size::new(0, 10)),
            Err(ClientError::InvalidRequest(
                RequestValidationError::EmptyPreferredSize
            ))
        ));
        assert!(matches!(
            client.set_minimum_size(Some(Size::new(10, 0))),
            Err(ClientError::InvalidRequest(
                RequestValidationError::EmptyMinimumSize
            ))
        ));
        assert!(matches!(
            client.set_maximum_size(Some(Size::new(0, 10))),
            Err(ClientError::InvalidRequest(
                RequestValidationError::EmptyMaximumSize
            ))
        ));
        assert_eq!(client.transport().sent.len(), sent_count);
    }

    #[test]
    fn redraw_pointer_keyboard_close_and_focus_events_translate_and_serialize() {
        let mut client = connected_client();
        let damage = vec![Rect::new(Point::new(1, 2), Size::new(3, 4))];
        let pointer = PointerEvent {
            position: Point::new(50, 60),
            kind: PointerEventKind::Button {
                button: PointerButton::Primary,
                state: ButtonState::Pressed,
            },
        };
        let keyboard = KeyboardEvent {
            usage: 0x04,
            state: ButtonState::Pressed,
            repeat: false,
            modifiers: Modifiers {
                shift: true,
                ..Modifiers::default()
            },
        };
        let cases = vec![
            (
                WireEvent::Redraw {
                    window_id: window_id(9),
                    damage: damage.clone(),
                },
                Event::Redraw {
                    window_id: window_id(9),
                    damage,
                },
            ),
            (
                WireEvent::Pointer {
                    window_id: window_id(9),
                    event: pointer,
                },
                Event::Pointer {
                    window_id: window_id(9),
                    event: pointer,
                },
            ),
            (
                WireEvent::Keyboard {
                    window_id: window_id(9),
                    event: keyboard,
                },
                Event::Keyboard {
                    window_id: window_id(9),
                    event: keyboard,
                },
            ),
            (
                WireEvent::CloseRequested {
                    window_id: window_id(9),
                },
                Event::CloseRequested {
                    window_id: window_id(9),
                },
            ),
            (
                WireEvent::FocusChanged {
                    window_id: window_id(9),
                    focused: true,
                },
                Event::FocusChanged {
                    window_id: window_id(9),
                    focused: true,
                },
            ),
        ];

        for (wire, expected) in cases {
            let encoded = postcard::to_allocvec(&wire).unwrap();
            let decoded: WireEvent = postcard::from_bytes(&encoded).unwrap();
            assert_eq!(decoded, wire);
            assert_eq!(
                client
                    .process_received(Received::new(decoded, Vec::new()))
                    .unwrap(),
                expected
            );
        }
    }

    #[test]
    fn configured_consumes_attachment_and_frame_offers_pixel_surface() {
        let mut client = connected_client();
        let ignored_drops = DropCount::default();
        let selected_drops = DropCount::default();
        let mut config = configuration(1, 2);
        config.format = PixelFormat::Argb8888;
        let event = client
            .process_received(Received::new(
                WireEvent::Configured(Configured {
                    window_id: window_id(9),
                    configuration: config,
                    surface_handle_index: 1,
                }),
                vec![
                    MockSurface::new(1, 1, ignored_drops.clone()),
                    MockSurface::new(
                        config.required_surface_bytes().unwrap(),
                        7,
                        selected_drops.clone(),
                    ),
                ],
            ))
            .unwrap();
        assert_eq!(
            event,
            Event::Configured {
                window_id: window_id(9),
                configuration: config,
            }
        );
        assert_eq!(ignored_drops.get(), 1);
        assert_eq!(selected_drops.get(), 0);

        let mut frame = client.acquire_frame().unwrap().unwrap();
        {
            let mut surface = frame.pixel_surface().unwrap();
            assert_eq!(surface.width(), 6);
            assert_eq!(surface.height(), 3);
            assert_eq!(surface.stride(), 24);
            assert_eq!(surface.format(), ginkgo_graphics::PixelFormat::Argb8888);
            surface.write_raw_pixel(0, 0, 0xaabb_ccdd);
        }
        assert_eq!(frame.bytes_mut().unwrap().len(), 72);
        assert_eq!(&frame.bytes_mut().unwrap()[..4], &[0xdd, 0xcc, 0xbb, 0xaa]);
    }

    #[test]
    fn rejects_invalid_attachments_and_non_increasing_generations() {
        let mut client = connected_client();
        let config = configuration(1, 2);
        assert!(matches!(
            client.process_received(Received::new(
                WireEvent::Configured(Configured {
                    window_id: window_id(9),
                    configuration: config,
                    surface_handle_index: 0,
                }),
                Vec::new(),
            )),
            Err(ClientError::Protocol(ProtocolError::MissingSurfaceHandle {
                index: 0
            }))
        ));

        assert!(matches!(
            client.process_received(Received::new(
                WireEvent::Configured(Configured {
                    window_id: window_id(9),
                    configuration: config,
                    surface_handle_index: 0,
                }),
                vec![MockSurface::new(4, 0, DropCount::default())],
            )),
            Err(ClientError::Protocol(ProtocolError::InvalidConfiguration(
                ConfigurationError::SurfaceTooShort
            )))
        ));

        configure(&mut client, 2, 2, DropCount::default());
        let stale = configuration(2, 2);
        assert!(matches!(
            client.process_received(Received::new(
                WireEvent::Configured(Configured {
                    window_id: window_id(9),
                    configuration: stale,
                    surface_handle_index: 0,
                }),
                vec![MockSurface::new(
                    stale.required_surface_bytes().unwrap(),
                    0,
                    DropCount::default(),
                )],
            )),
            Err(ClientError::Protocol(ProtocolError::StaleGeneration { .. }))
        ));
    }

    #[test]
    fn dropping_an_unpresented_frame_returns_its_slot() {
        let mut client = connected_client();
        configure(&mut client, 1, 2, DropCount::default());
        let first_id = {
            let frame = client.acquire_frame().unwrap().unwrap();
            frame.buffer_id()
        };
        let frame = client.acquire_frame().unwrap().unwrap();
        assert_eq!(frame.buffer_id(), first_id);
    }

    #[test]
    fn presented_buffers_require_matching_release_before_reacquisition() {
        let mut client = connected_client();
        configure(&mut client, 1, 2, DropCount::default());

        let first = client.acquire_frame().unwrap().unwrap();
        let first_buffer = first.buffer_id();
        let first_present = first.present(Vec::new()).unwrap();
        let second = client.acquire_frame().unwrap().unwrap();
        let second_buffer = second.buffer_id();
        let second_present = second.present(Vec::new()).unwrap();
        assert_ne!(first_buffer, second_buffer);
        assert!(client.acquire_frame().unwrap().is_none());

        assert!(matches!(
            client.process_received(Received::new(
                WireEvent::BufferReleased {
                    window_id: window_id(9),
                    generation: generation(1),
                    buffer_id: first_buffer,
                    present_request_id: second_present,
                },
                Vec::new(),
            )),
            Err(ClientError::Protocol(
                ProtocolError::PresentRequestMismatch { .. }
            ))
        ));
        assert!(client.acquire_frame().unwrap().is_none());

        client
            .process_received(Received::new(
                WireEvent::BufferReleased {
                    window_id: window_id(9),
                    generation: generation(1),
                    buffer_id: first_buffer,
                    present_request_id: first_present,
                },
                Vec::new(),
            ))
            .unwrap();
        let frame = client.acquire_frame().unwrap().unwrap();
        assert_eq!(frame.buffer_id(), first_buffer);
    }

    #[test]
    fn failed_present_restores_an_active_generation_buffer() {
        let mut client = connected_client();
        configure(&mut client, 1, 2, DropCount::default());
        let frame = client.acquire_frame().unwrap().unwrap();
        let buffer_id = frame.buffer_id();
        let present_request_id = frame.present(Vec::new()).unwrap();

        assert_eq!(
            client
                .process_received(Received::new(
                    WireEvent::RequestFailed {
                        request_id: present_request_id,
                        code: ServerErrorCode::InvalidRequest,
                    },
                    Vec::new(),
                ))
                .unwrap(),
            Event::RequestFailed {
                request_id: present_request_id,
                code: ServerErrorCode::InvalidRequest,
            }
        );
        let frame = client.acquire_frame().unwrap().unwrap();
        assert_eq!(frame.buffer_id(), buffer_id);
    }

    #[test]
    fn two_failed_presents_do_not_deadlock_acquisition() {
        let mut client = connected_client();
        configure(&mut client, 1, 2, DropCount::default());
        let first_request = client
            .acquire_frame()
            .unwrap()
            .unwrap()
            .present(Vec::new())
            .unwrap();
        let second_request = client
            .acquire_frame()
            .unwrap()
            .unwrap()
            .present(Vec::new())
            .unwrap();
        assert!(client.acquire_frame().unwrap().is_none());

        for request_id in [first_request, second_request] {
            client
                .process_received(Received::new(
                    WireEvent::RequestFailed {
                        request_id,
                        code: ServerErrorCode::InvalidRequest,
                    },
                    Vec::new(),
                ))
                .unwrap();
        }

        let first = client.acquire_frame().unwrap().unwrap();
        let first_buffer = first.buffer_id();
        first.present(Vec::new()).unwrap();
        let second = client.acquire_frame().unwrap().unwrap();
        assert_ne!(second.buffer_id(), first_buffer);
    }

    #[test]
    fn failed_present_removes_an_idle_retired_generation() {
        let mut client = connected_client();
        let old_drops = DropCount::default();
        configure(&mut client, 1, 2, old_drops.clone());
        let old_request = client
            .acquire_frame()
            .unwrap()
            .unwrap()
            .present(Vec::new())
            .unwrap();
        configure(&mut client, 2, 2, DropCount::default());
        assert_eq!(old_drops.get(), 0);

        client
            .process_received(Received::new(
                WireEvent::RequestFailed {
                    request_id: old_request,
                    code: ServerErrorCode::InvalidRequest,
                },
                Vec::new(),
            ))
            .unwrap();
        assert_eq!(old_drops.get(), 1);
        assert_eq!(
            client.acquire_frame().unwrap().unwrap().generation(),
            generation(2)
        );
    }

    #[test]
    fn resize_keeps_old_in_flight_pool_until_release() {
        let mut client = connected_client();
        let old_drops = DropCount::default();
        let new_drops = DropCount::default();
        configure(&mut client, 1, 2, old_drops.clone());

        let old_frame = client.acquire_frame().unwrap().unwrap();
        let old_buffer = old_frame.buffer_id();
        let old_present = old_frame.present(Vec::new()).unwrap();
        configure(&mut client, 2, 2, new_drops.clone());
        assert_eq!(old_drops.get(), 0);
        assert_eq!(
            client.active_configuration().unwrap().generation,
            generation(2)
        );

        let new_frame = client.acquire_frame().unwrap().unwrap();
        assert_eq!(new_frame.generation(), generation(2));
        drop(new_frame);

        client
            .process_received(Received::new(
                WireEvent::BufferReleased {
                    window_id: window_id(9),
                    generation: generation(1),
                    buffer_id: old_buffer,
                    present_request_id: old_present,
                },
                Vec::new(),
            ))
            .unwrap();
        assert_eq!(old_drops.get(), 1);
        assert_eq!(new_drops.get(), 0);
    }

    #[test]
    fn resize_immediately_drops_an_idle_old_pool() {
        let mut client = connected_client();
        let old_drops = DropCount::default();
        configure(&mut client, 1, 2, old_drops.clone());
        configure(&mut client, 2, 2, DropCount::default());
        assert_eq!(old_drops.get(), 1);
        assert!(matches!(
            client.process_received(Received::new(
                WireEvent::BufferReleased {
                    window_id: window_id(9),
                    generation: generation(1),
                    buffer_id: BufferId::new(0),
                    present_request_id: request_id(10),
                },
                Vec::new(),
            )),
            Err(ClientError::Protocol(ProtocolError::UnknownGeneration(value)))
                if value == generation(1)
        ));
    }

    #[test]
    fn present_request_contains_generation_buffer_and_damage() {
        let mut client = connected_client();
        configure(&mut client, 3, 2, DropCount::default());
        let frame = client.acquire_frame().unwrap().unwrap();
        let buffer_id = frame.buffer_id();
        let damage = vec![Rect::new(Point::new(1, 2), Size::new(3, 1))];
        let present_id = frame.present(damage.clone()).unwrap();

        assert_eq!(
            client.transport().sent.last(),
            Some(&WireRequest::Present {
                request_id: present_id,
                window_id: window_id(9),
                generation: generation(3),
                buffer_id,
                damage,
            })
        );
    }
}
