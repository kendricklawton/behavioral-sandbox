//! The frame on screen: a texture the size of the scanout, and an upload per present of the part
//! that changed, read straight out of the mapped slot.
//!
//! - **One upload per redraw, of the union of what changed.** The window redraws at the panel's
//!   pace and the guest presents at its own; the upload covers every present since the frame the
//!   texture holds, found by frame id in the history the primitive carries.
//! - **A slot is read after the guest may have moved on.** The helper frees a slot two presents
//!   after it was the latest, so a very late upload tears; it never faults, because the mapping's
//!   size is sealed.
//! - **The widget's events are the guest's input.** A key, a pointer move against where the
//!   frame sits, a button or a wheel becomes `bsx_input`'s report and travels as its lines down
//!   the input session; losing the window's focus releases everything held.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use iced::keyboard::key::{NativeCode, Physical};
use iced::wgpu;
use iced::widget::shader::{self, Viewport};
use iced::{Event, Rectangle, keyboard, mouse, window};

use bsx_input::{Area, Button, Held, InputEvent, Target, format_line};
use bsx_krun::{PixelFormat, SharedFrames, SharedLayout};
use bsx_supervisor::control::Damage;

/// One present as the lease reported it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Present {
    pub(crate) frame_id: u32,
    pub(crate) slot: u32,
    pub(crate) damage: Damage,
}

/// Where an upload is recorded (a count, and a log line per upload when asked for), and where
/// each input line goes beside the session when asked for.
#[derive(Debug)]
pub(crate) struct Sinks {
    uploaded: AtomicU64,
    log: Mutex<Option<std::fs::File>>,
    input: Mutex<Option<std::fs::File>>,
}

impl Sinks {
    pub(crate) fn open(
        log: Option<&std::path::Path>,
        input: Option<&std::path::Path>,
    ) -> std::io::Result<Self> {
        Ok(Self {
            uploaded: AtomicU64::new(0),
            log: Mutex::new(log.map(std::fs::File::create).transpose()?),
            input: Mutex::new(input.map(std::fs::File::create).transpose()?),
        })
    }

    fn sent(&self, line: &str) {
        let mut log = self
            .input
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(log) = log.as_mut() {
            let _ = writeln!(log, "{line}");
        }
    }

    pub(crate) fn uploaded(&self) -> u64 {
        self.uploaded.load(Ordering::Relaxed)
    }

    /// Records an upload of `frame_id` that took `took_ns` in `write_texture`: the log line is
    /// the frame id, the clock at the upload, and that duration.
    fn record(&self, frame_id: u32, took_ns: u64) {
        self.uploaded.fetch_add(1, Ordering::Relaxed);
        let mut log = self
            .log
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(log) = log.as_mut() {
            let _ = writeln!(
                log,
                "{frame_id}\t{}\t{took_ns}",
                crate::lease::monotonic_ns()
            );
        }
    }
}

/// The widget's program: what the view hands the shader widget each time it is built.
#[derive(Debug)]
pub(crate) struct Program {
    pub(crate) run: Arc<str>,
    pub(crate) frames: Arc<SharedFrames>,
    pub(crate) history: Arc<VecDeque<Present>>,
    pub(crate) sinks: Arc<Sinks>,
    /// Where a report's lines go: the writer thread's end, never the socket itself, so a guest
    /// that stops reading cannot stall the thread iced draws on.
    pub(crate) input: Option<iced::futures::channel::mpsc::UnboundedSender<String>>,
}

impl<Message> shader::Program<Message> for Program {
    /// What the guest thinks is down, released when the window loses focus.
    type State = Held;
    type Primitive = Primitive;

    fn update(
        &self,
        held: &mut Held,
        event: &Event,
        bounds: Rectangle,
        _cursor: mouse::Cursor,
    ) -> Option<shader::Action<Message>> {
        let lines = self.input.as_ref()?;
        let mut sent_any = false;
        let mut send = |target: Target, events: &[InputEvent]| {
            for event in events {
                let line = format_line(target, event);
                self.sinks.sent(&line);
                let _ = lines.unbounded_send(line);
                sent_any = true;
            }
        };
        match event {
            Event::Keyboard(keyboard::Event::KeyPressed {
                physical_key,
                repeat,
                ..
            }) => {
                let action = bsx_input::KeyAction::of(true, *repeat);
                if let Some(report) =
                    scancode(physical_key).and_then(|code| bsx_input::key(code, action))
                {
                    held.key(report[0].code, action.is_down());
                    send(Target::Keyboard, &report);
                }
            }
            Event::Keyboard(keyboard::Event::KeyReleased { physical_key, .. }) => {
                if let Some(report) = scancode(physical_key)
                    .and_then(|code| bsx_input::key(code, bsx_input::KeyAction::Release))
                {
                    held.key(report[0].code, false);
                    send(Target::Keyboard, &report);
                }
            }
            Event::Mouse(mouse::Event::CursorMoved { position }) => {
                let layout = self.frames.layout();
                let place = fit(bounds, layout.width, layout.height);
                let area = Area::new(
                    f64::from(place.x),
                    f64::from(place.y),
                    f64::from(place.width),
                    f64::from(place.height),
                );
                send(
                    Target::Pointer,
                    &bsx_input::position(f64::from(position.x), f64::from(position.y), area),
                );
            }
            Event::Mouse(mouse::Event::ButtonPressed(button)) => {
                if let Some(code) = button_of(*button) {
                    held.button(code, true);
                    send(Target::Pointer, &bsx_input::button(code, true));
                }
            }
            Event::Mouse(mouse::Event::ButtonReleased(button)) => {
                if let Some(code) = button_of(*button) {
                    held.button(code, false);
                    send(Target::Pointer, &bsx_input::button(code, false));
                }
            }
            Event::Mouse(mouse::Event::WheelScrolled { delta }) => {
                let (dx, dy) = match *delta {
                    mouse::ScrollDelta::Lines { x, y } => (f64::from(x), f64::from(y)),
                    // The window's pixel count as a line; `wheel` rounds and clamps it.
                    mouse::ScrollDelta::Pixels { x, y } => (
                        f64::from(x) / bsx_input::WHEEL_LINE_PIXELS,
                        f64::from(y) / bsx_input::WHEEL_LINE_PIXELS,
                    ),
                };
                let report = bsx_input::wheel(dx, dy);
                if !report.is_empty() {
                    send(Target::Pointer, &report);
                }
            }
            Event::Window(window::Event::Unfocused) => {
                let (keys, buttons) = held.release_all();
                if !keys.is_empty() {
                    send(Target::Keyboard, &keys);
                }
                if !buttons.is_empty() {
                    send(Target::Pointer, &buttons);
                }
            }
            _ => {}
        }
        // What went to the guest is the guest's: capturing stops the same key or click also
        // driving a widget behind the frame.
        sent_any.then(shader::Action::capture)
    }

    fn draw(&self, _state: &Held, _cursor: mouse::Cursor, _bounds: Rectangle) -> Primitive {
        Primitive {
            run: Arc::clone(&self.run),
            frames: Arc::clone(&self.frames),
            history: Arc::clone(&self.history),
            sinks: Arc::clone(&self.sinks),
        }
    }
}

/// The evdev code of the physical key iced reports: by the key's UI Events name, or the xkb
/// number of one it could not name, which winit reports as the scancode itself.
fn scancode(key: &Physical) -> Option<u32> {
    match key {
        Physical::Code(code) => bsx_input::key_code(&format!("{code:?}")).map(u32::from),
        Physical::Unidentified(NativeCode::Xkb(raw)) => Some(*raw),
        Physical::Unidentified(_) => None,
    }
}

/// The evdev code of a mouse button, or `None` for one the pointer does not emit.
fn button_of(button: mouse::Button) -> Option<u16> {
    Some(bsx_input::button_code(match button {
        mouse::Button::Left => Button::Left,
        mouse::Button::Right => Button::Right,
        mouse::Button::Middle => Button::Middle,
        mouse::Button::Back => Button::Back,
        mouse::Button::Forward => Button::Forward,
        mouse::Button::Other(_) => return None,
    }))
}

/// What one redraw draws: the latest present in `history`, uploaded from `frames`.
///
/// `run` keys its texture in the [`Pipeline`], which iced shares across every frame on screen.
#[derive(Debug)]
pub(crate) struct Primitive {
    run: Arc<str>,
    frames: Arc<SharedFrames>,
    history: Arc<VecDeque<Present>>,
    sinks: Arc<Sinks>,
}

impl shader::Primitive for Primitive {
    type Pipeline = Pipeline;

    fn prepare(
        &self,
        pipeline: &mut Pipeline,
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        bounds: &Rectangle,
        viewport: &Viewport,
    ) {
        let layout = self.frames.layout();
        let Some(latest) = self.history.back().copied() else {
            return;
        };
        let scale = viewport.scale_factor();
        let place = fit(
            Rectangle {
                x: bounds.x * scale,
                y: bounds.y * scale,
                width: bounds.width * scale,
                height: bounds.height * scale,
            },
            layout.width,
            layout.height,
        );
        let Some(texture) = pipeline.texture_for(&self.run, device, &layout) else {
            return;
        };
        // Where it goes is recorded even when the frame it holds is already the latest: the
        // window can be resized without the guest presenting anything new.
        texture.place = place;
        if texture.holds == Some(latest.frame_id) {
            return;
        }
        let damage = changed_since(&self.history, texture.holds)
            .unwrap_or_else(|| Damage::new(0, 0, layout.width, layout.height));
        let Some(view) = self.frames.frame(latest.frame_id, latest.slot) else {
            return;
        };
        let Some(region) = Region::of(damage, &layout) else {
            return;
        };
        let Some(data) = view.pixels.get(region.offset..) else {
            return;
        };
        let started = crate::lease::monotonic_ns();
        queue.write_texture(
            wgpu::TexelCopyTextureInfo {
                texture: &texture.texture,
                mip_level: 0,
                origin: wgpu::Origin3d {
                    x: region.x,
                    y: region.y,
                    z: 0,
                },
                aspect: wgpu::TextureAspect::All,
            },
            data,
            wgpu::TexelCopyBufferLayout {
                offset: 0,
                bytes_per_row: Some(layout.stride),
                rows_per_image: None,
            },
            wgpu::Extent3d {
                width: region.width,
                height: region.height,
                depth_or_array_layers: 1,
            },
        );
        texture.holds = Some(latest.frame_id);
        self.sinks
            .record(latest.frame_id, crate::lease::monotonic_ns() - started);
    }

    fn draw(&self, pipeline: &Pipeline, pass: &mut wgpu::RenderPass<'_>) -> bool {
        let Some(texture) = pipeline.textures.get(&self.run) else {
            return true;
        };
        let place = texture.place;
        pass.set_viewport(place.x, place.y, place.width, place.height, 0.0, 1.0);
        pass.set_pipeline(&pipeline.render);
        pass.set_bind_group(0, &texture.bind_group, &[]);
        pass.draw(0..3, 0..1);
        true
    }
}

/// The union of the damage of every present after the one with id `since`, or `None` when
/// `since` is not in the history (the texture holds a frame too old to build on).
fn changed_since(history: &VecDeque<Present>, since: Option<u32>) -> Option<Damage> {
    let at = history.iter().position(|p| Some(p.frame_id) == since)?;
    history.iter().skip(at + 1).map(|p| p.damage).reduce(union)
}

/// The smallest rectangle holding both.
pub(crate) fn union(a: Damage, b: Damage) -> Damage {
    let left = a.x.min(b.x);
    let top = a.y.min(b.y);
    let right = a.x.saturating_add(a.width).max(b.x.saturating_add(b.width));
    let bottom =
        a.y.saturating_add(a.height)
            .max(b.y.saturating_add(b.height));
    Damage::new(left, top, right - left, bottom - top)
}

/// The part of a slot one upload reads: where it starts in the slot's bytes, and its extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Region {
    offset: usize,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

impl Region {
    /// `damage` clipped to the frame, or `None` for a damage with nothing inside the frame.
    fn of(damage: Damage, layout: &SharedLayout) -> Option<Self> {
        let x = damage.x.min(layout.width);
        let y = damage.y.min(layout.height);
        let width = damage.width.min(layout.width - x);
        let height = damage.height.min(layout.height - y);
        if width == 0 || height == 0 {
            return None;
        }
        let bytes = layout.format.bytes_per_pixel()?.get();
        let offset = (y as usize)
            .checked_mul(layout.stride as usize)?
            .checked_add((x as usize).checked_mul(bytes)?)?;
        Some(Self {
            offset,
            x,
            y,
            width,
            height,
        })
    }
}

/// Where a `width` by `height` frame goes inside `bounds`, keeping its aspect: the largest fit,
/// centred. In the same pixels as `bounds`.
fn fit(bounds: Rectangle, width: u32, height: u32) -> Rectangle {
    if width == 0 || height == 0 || bounds.width <= 0.0 || bounds.height <= 0.0 {
        return bounds;
    }
    let (w, h) = if bounds.width * height as f32 <= bounds.height * width as f32 {
        let w = bounds.width.floor();
        (w, (w * height as f32 / width as f32).floor())
    } else {
        let h = bounds.height.floor();
        ((h * width as f32 / height as f32).floor(), h)
    };
    let (w, h) = (w.max(1.0), h.max(1.0));
    Rectangle {
        x: bounds.x + ((bounds.width - w) / 2.0).floor(),
        y: bounds.y + ((bounds.height - h) / 2.0).floor(),
        width: w,
        height: h,
    }
}

/// The wgpu format a scanout's pixels upload as, matched to the target's colour encoding so a
/// sample and the write cancel out, or `None` for a layout no wgpu texture has.
fn texture_format(format: PixelFormat, srgb: bool) -> Option<wgpu::TextureFormat> {
    match (format, srgb) {
        (PixelFormat::B8G8R8A8Unorm | PixelFormat::B8G8R8X8Unorm, false) => {
            Some(wgpu::TextureFormat::Bgra8Unorm)
        }
        (PixelFormat::B8G8R8A8Unorm | PixelFormat::B8G8R8X8Unorm, true) => {
            Some(wgpu::TextureFormat::Bgra8UnormSrgb)
        }
        (PixelFormat::R8G8B8A8Unorm | PixelFormat::R8G8B8X8Unorm, false) => {
            Some(wgpu::TextureFormat::Rgba8Unorm)
        }
        (PixelFormat::R8G8B8A8Unorm | PixelFormat::R8G8B8X8Unorm, true) => {
            Some(wgpu::TextureFormat::Rgba8UnormSrgb)
        }
        _ => None,
    }
}

/// The texture holding one run's frame, which frame it holds, and where it goes.
#[derive(Debug)]
struct Texture {
    texture: wgpu::Texture,
    bind_group: wgpu::BindGroup,
    layout: SharedLayout,
    holds: Option<u32>,
    /// Where the frame goes in the target, in physical pixels. Per run, because iced runs every
    /// `prepare` before any `draw`: a single field would hold the last one prepared.
    place: Rectangle,
    /// When this run's frame was last prepared, for the eviction below.
    used: u64,
}

/// The most runs whose textures are kept at once. A grid shows what is running, and a long
/// session would otherwise leave a texture behind for every sandbox ever watched. Above
/// `crate::MAX_THUMBNAILS`, so the grid's leases plus the open run always have one each.
pub(crate) const MAX_TEXTURES: usize = 16;

/// What every [`Primitive`] shares: the render pipeline for the target format, and one texture
/// per run on screen.
#[derive(Debug)]
pub(crate) struct Pipeline {
    render: wgpu::RenderPipeline,
    bind_layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    target: wgpu::TextureFormat,
    textures: std::collections::HashMap<Arc<str>, Texture>,
    /// Bumped per prepare, so the least recently prepared run is the one evicted.
    tick: u64,
    refused: Option<PixelFormat>,
}

impl Pipeline {
    /// The texture for `layout`, made on first use and remade when the layout changes, or `None`
    /// for a format this build cannot upload (said once).
    fn texture_for(
        &mut self,
        run: &Arc<str>,
        device: &wgpu::Device,
        layout: &SharedLayout,
    ) -> Option<&mut Texture> {
        self.tick += 1;
        if self.textures.get(run).is_some_and(|t| t.layout != *layout) {
            self.textures.remove(run);
        }
        if !self.textures.contains_key(run) {
            let Some(format) = texture_format(layout.format, self.target.is_srgb()) else {
                if self.refused != Some(layout.format) {
                    eprintln!(
                        "bsx-app: {:?} is not a format this build uploads",
                        layout.format
                    );
                    self.refused = Some(layout.format);
                }
                return None;
            };
            let texture = device.create_texture(&wgpu::TextureDescriptor {
                label: Some("bsx frame"),
                size: wgpu::Extent3d {
                    width: layout.width,
                    height: layout.height,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            });
            let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("bsx frame"),
                layout: &self.bind_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: wgpu::BindingResource::TextureView(&view),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: wgpu::BindingResource::Sampler(&self.sampler),
                    },
                ],
            });
            // Evict before inserting, so the map never holds more than the cap.
            while self.textures.len() >= MAX_TEXTURES {
                let Some(oldest) = self
                    .textures
                    .iter()
                    .min_by_key(|(_, t)| t.used)
                    .map(|(k, _)| Arc::clone(k))
                else {
                    break;
                };
                self.textures.remove(&oldest);
            }
            self.textures.insert(
                Arc::clone(run),
                Texture {
                    texture,
                    bind_group,
                    layout: *layout,
                    holds: None,
                    place: Rectangle::default(),
                    used: self.tick,
                },
            );
        }
        let tick = self.tick;
        let texture = self.textures.get_mut(run)?;
        texture.used = tick;
        Some(texture)
    }
}

/// A triangle covering the viewport, sampling the frame; the X channel is ignored.
const SHADER: &str = r#"
struct Out {
    @builtin(position) position: vec4<f32>,
    @location(0) uv: vec2<f32>,
};

@vertex
fn vs_main(@builtin(vertex_index) index: u32) -> Out {
    let x = f32(i32(index & 1u) * 4 - 1);
    let y = f32(i32(index & 2u) * 2 - 1);
    var out: Out;
    out.position = vec4<f32>(x, y, 0.0, 1.0);
    out.uv = vec2<f32>((x + 1.0) * 0.5, 1.0 - (y + 1.0) * 0.5);
    return out;
}

@group(0) @binding(0) var frame: texture_2d<f32>;
@group(0) @binding(1) var frame_sampler: sampler;

@fragment
fn fs_main(in: Out) -> @location(0) vec4<f32> {
    return vec4<f32>(textureSample(frame, frame_sampler, in.uv).rgb, 1.0);
}
"#;

impl shader::Pipeline for Pipeline {
    fn new(device: &wgpu::Device, _queue: &wgpu::Queue, format: wgpu::TextureFormat) -> Self {
        eprintln!("bsx-app: target format {format:?}");
        let module = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("bsx frame"),
            source: wgpu::ShaderSource::Wgsl(SHADER.into()),
        });
        let bind_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("bsx frame"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });
        let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("bsx frame"),
            bind_group_layouts: &[&bind_layout],
            push_constant_ranges: &[],
        });
        let render = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("bsx frame"),
            layout: Some(&layout),
            vertex: wgpu::VertexState {
                module: &module,
                entry_point: Some("vs_main"),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                buffers: &[],
            },
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            fragment: Some(wgpu::FragmentState {
                module: &module,
                entry_point: Some("fs_main"),
                compilation_options: wgpu::PipelineCompilationOptions::default(),
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: None,
                    write_mask: wgpu::ColorWrites::ALL,
                })],
            }),
            multiview: None,
            cache: None,
        });
        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("bsx frame"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..wgpu::SamplerDescriptor::default()
        });
        Self {
            render,
            bind_layout,
            sampler,
            target: format,
            textures: std::collections::HashMap::new(),
            tick: 0,
            refused: None,
        }
    }
}

/// Prints the adapter wgpu picks on this host, as iced will: the answer to "does wgpu come up
/// on this GPU, and with which backend".
pub(crate) fn report_adapter() {
    let instance = wgpu::Instance::new(&wgpu::InstanceDescriptor::from_env_or_default());
    let picked = iced::futures::executor::block_on(
        instance.request_adapter(&wgpu::RequestAdapterOptions::default()),
    );
    match picked {
        Ok(adapter) => {
            let info = adapter.get_info();
            eprintln!(
                "bsx-app: wgpu adapter {:?}, backend {:?}, driver {:?} {:?}",
                info.name, info.backend, info.driver, info.driver_info
            );
        }
        Err(e) => eprintln!("bsx-app: wgpu found no adapter: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout(width: u32, height: u32) -> SharedLayout {
        SharedLayout::new(
            width,
            height,
            PixelFormat::B8G8R8X8Unorm,
            width * 4,
            4,
            u64::from(width * height * 4),
            1,
        )
    }

    fn present(frame_id: u32, damage: Damage) -> Present {
        Present {
            frame_id,
            slot: 0,
            damage,
        }
    }

    /// The upload after a run of missed redraws covers every present since the frame the texture
    /// holds, and only those; a texture holding a frame the history has forgotten gets all of it.
    #[test]
    fn the_upload_covers_what_changed_since_the_frame_the_texture_holds() {
        let history: VecDeque<Present> = VecDeque::from(vec![
            present(10, Damage::new(0, 0, 640, 480)),
            present(11, Damage::new(10, 10, 5, 5)),
            present(12, Damage::new(100, 200, 20, 10)),
            present(13, Damage::new(0, 0, 16, 16)),
        ]);
        assert_eq!(
            changed_since(&history, Some(11)),
            Some(Damage::new(0, 0, 120, 210)),
            "12 and 13 together"
        );
        assert_eq!(
            changed_since(&history, Some(13)),
            None,
            "nothing after the latest"
        );
        assert_eq!(
            changed_since(&history, Some(9)),
            None,
            "a frame the history has forgotten"
        );
        assert_eq!(changed_since(&history, None), None, "no frame yet");
    }

    /// A damage is clipped to the frame, its bytes start at its top-left pixel, and one with
    /// nothing inside the frame is no upload.
    #[test]
    fn a_region_is_the_damage_clipped_to_the_frame() {
        let l = layout(640, 480);
        assert_eq!(
            Region::of(Damage::new(10, 20, 30, 40), &l),
            Some(Region {
                offset: 20 * 640 * 4 + 10 * 4,
                x: 10,
                y: 20,
                width: 30,
                height: 40,
            })
        );
        assert_eq!(
            Region::of(Damage::new(630, 470, 100, 100), &l),
            Some(Region {
                offset: 470 * 640 * 4 + 630 * 4,
                x: 630,
                y: 470,
                width: 10,
                height: 10,
            }),
            "clipped at the right and bottom edges"
        );
        assert_eq!(Region::of(Damage::new(640, 0, 1, 1), &l), None, "outside");
        assert_eq!(Region::of(Damage::new(0, 0, 0, 5), &l), None, "empty");
    }

    /// The frame keeps its aspect inside the widget, centred, and fills one axis.
    #[test]
    fn the_frame_is_letterboxed_into_the_bounds() {
        let bounds = Rectangle {
            x: 0.0,
            y: 0.0,
            width: 1000.0,
            height: 500.0,
        };
        assert_eq!(
            fit(bounds, 640, 480),
            Rectangle {
                x: 167.0,
                y: 0.0,
                width: 666.0,
                height: 500.0
            }
        );
        let tall = Rectangle {
            x: 10.0,
            y: 10.0,
            width: 320.0,
            height: 1000.0,
        };
        assert_eq!(
            fit(tall, 640, 480),
            Rectangle {
                x: 10.0,
                y: 390.0,
                width: 320.0,
                height: 240.0
            }
        );
    }

    /// iced's physical keys become evdev codes by name, an xkb number it could not name passes
    /// through, and its buttons become the pointer's codes.
    #[test]
    fn iced_keys_and_buttons_become_evdev_codes() {
        use iced::keyboard::key::Code;
        assert_eq!(scancode(&Physical::Code(Code::KeyA)), Some(30));
        assert_eq!(scancode(&Physical::Code(Code::Enter)), Some(28));
        assert_eq!(scancode(&Physical::Code(Code::Hyper)), None);
        assert_eq!(
            scancode(&Physical::Unidentified(NativeCode::Xkb(240))),
            Some(240)
        );
        assert_eq!(
            scancode(&Physical::Unidentified(NativeCode::Unidentified)),
            None
        );
        assert_eq!(button_of(mouse::Button::Left), Some(bsx_input::BTN_LEFT));
        assert_eq!(
            button_of(mouse::Button::Forward),
            Some(bsx_input::BTN_EXTRA)
        );
        assert_eq!(button_of(mouse::Button::Other(9)), None);
    }

    /// The texture's colour encoding follows the target's, so a sample and the write cancel.
    #[test]
    fn the_texture_format_follows_the_target() {
        assert_eq!(
            texture_format(PixelFormat::B8G8R8X8Unorm, true),
            Some(wgpu::TextureFormat::Bgra8UnormSrgb)
        );
        assert_eq!(
            texture_format(PixelFormat::R8G8B8A8Unorm, false),
            Some(wgpu::TextureFormat::Rgba8Unorm)
        );
        assert_eq!(texture_format(PixelFormat::A8R8G8B8Unorm, false), None);
        assert_eq!(texture_format(PixelFormat::Unknown(7), true), None);
    }
}
