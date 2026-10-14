use clap::Parser;
use clap_derive::Parser;
use gtk_display::{
    Axis, DisplayBackendHandle, DisplayInputOptions, InputBackendHandle, TouchArea,
    TouchScreenOptions,
};

use log::LevelFilter;
use regex::{Captures, Regex};
use std::ffi::CString;
use std::fmt::Display;
use std::fs::File;
use std::io;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::{LazyLock, OnceLock};
use std::thread;

use anyhow::Context;
use krun::{DeviceManager, VirglRendererFlags};
use libloading::os::unix::{Library, RTLD_GLOBAL, RTLD_NOW};

static LIBKRUN: OnceLock<Library> = OnceLock::new();

#[derive(Debug, Copy, Clone)]
pub enum PhysicalSize {
    Dpi(u32),
    DimensionsMillimeters(u16, u16),
}

#[derive(Debug, Clone, Copy)]
struct DisplayArg {
    width: u32,
    height: u32,
    refresh_rate: Option<u32>,
    physical_size: Option<PhysicalSize>,
    touch: bool,
}

/// Parses a display settings string.
/// The expected format is "WIDTHxHEIGHT[@FPS][:DPIdpi|:PHYSICAL_WIDTHxPHYSICAL_HEIGHTmm]".
fn parse_display(display_string: &str) -> Result<DisplayArg, String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^(?P<width>\d+)x(?P<height>\d+)(?:@(?P<refresh_rate>\d+))?(?::(?P<dpi>\d+)dpi|:(?P<width_mm>\d+)x(?P<height_mm>\d+)mm)?(?P<touch>\+touch(screen)?)?$",
        ).unwrap()
    });

    let captures = RE.captures(display_string).ok_or_else(|| {
        format!("Invalid display string '{display_string}' format. Examples of valid values:\n '1920x1080', '1920x1080+touch','1920x1080@60', '1920x1080:162x91mm', '1920x1080:300dpi', '1920x1080@90:300dpi+touch'")
    })?;

    fn parse_group<T: FromStr>(captures: &Captures, name: &str) -> Result<Option<T>, String>
    where
        T::Err: Display,
    {
        captures
            .name(name)
            .map(|match_| {
                match_
                    .as_str()
                    .parse::<T>()
                    .map_err(|e| format!("Failed to parse {name}: {e}"))
            })
            .transpose()
    }

    Ok(DisplayArg {
        width: parse_group(&captures, "width")?.expect("regex bug"),
        height: parse_group(&captures, "height")?.expect("regex bug"),
        refresh_rate: parse_group(&captures, "refresh_rate")?,
        physical_size: match (
            parse_group(&captures, "dpi")?,
            parse_group(&captures, "width_mm")?,
            parse_group(&captures, "height_mm")?,
        ) {
            (Some(dpi), None, None) => Some(PhysicalSize::Dpi(dpi)),
            (None, Some(width_mm), Some(height_mm)) => {
                Some(PhysicalSize::DimensionsMillimeters(width_mm, height_mm))
            }
            (None, None, None) => None,
            _ => unreachable!("regex bug"),
        },
        touch: captures.name("touch").is_some(),
    })
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(long)]
    root_dir: CString,

    executable: Option<CString>,
    argv: Vec<CString>,

    // Display specifications in the format WIDTHxHEIGHT[@FPS][:DPIdpi|:PHYSICAL_WIDTHxPHYSICAL_HEIGHTmm]
    #[clap(long, value_parser = parse_display)]
    display: Vec<DisplayArg>,

    /// Attach a virtual keyboard input device
    #[arg(long)]
    keyboard_input: bool,

    /// Pipe (or file) where to write log (with terminal color formatting)
    #[arg(long)]
    color_log: Option<PathBuf>,

    /// Passthrough an input device (e.g. /dev/input/event0)
    #[arg(long)]
    input: Vec<PathBuf>,

    /// Use vhost-user GPU backend at the given socket path (disables built-in GPU)
    #[arg(long)]
    vhost_user_gpu: Option<PathBuf>,
}

/// Load libkrun and resolve the symbols this example needs from its namespace.
fn load_krun() -> anyhow::Result<()> {
    LIBKRUN.get_or_init(|| {
        let name = if cfg!(target_os = "macos") {
            "libkrun.dylib"
        } else {
            "libkrun.so"
        };
        unsafe { Library::open(Some(name), RTLD_NOW | RTLD_GLOBAL) }
            .expect("failed to dlopen libkrun")
    });

    use krun::Symbol::*;
    let mut symbols = vec![
        KrunInitLog,
        KrunErrorResult,
        KrunErrorMessage,
        KrunErrorDestroy,
        KrunMmioDeviceManagerNew,
        KrunMmioDeviceManagerAdd,
        KrunMmioDeviceManagerDestroy,
        KrunFsDeviceNew,
        KrunFsDeviceSetOverlay,
        KrunFsDeviceDestroy,
        KrunFsOverlayNew,
        KrunFsOverlayDestroy,
        KrunConsoleDeviceBuilder,
        KrunConsoleBuilderAddDefaultConsole,
        KrunConsoleBuilderBuild,
        KrunConsoleBuilderDestroy,
        KrunConsoleDeviceDestroy,
        KrunPayloadLoadKrunfw,
        KrunPayloadDestroy,
        KrunDisplayBackendNew,
        KrunDisplayBackendAddDisplay,
        KrunDisplayBackendDestroy,
        KrunDisplayInfoBuilderNew,
        KrunDisplayInfoBuilderDestroy,
        KrunDisplayInfoBuilderDpi,
        KrunDisplayInfoBuilderPhysicalSize,
        KrunDisplayInfoBuilderRefreshRate,
        KrunGpuDeviceNew,
        KrunGpuDeviceDestroy,
        KrunInputDeviceNew,
        KrunInputDeviceNewFromFd,
        KrunInputDeviceDestroy,
        KrunVmmBuilderNew,
        KrunVmmBuilderVcpus,
        KrunVmmBuilderRamMib,
        KrunVmmBuilderPayload,
        KrunVmmBuilderDevices,
        KrunVmmBuilderBuild,
        KrunVmmBuilderDestroy,
        KrunVmmDestroy,
        KrunVmmRun,
    ];
    #[cfg(target_os = "linux")]
    symbols.extend([
        KrunVhostUserDeviceNew,
        KrunVhostUserDeviceSetDisplayBackend,
        KrunVhostUserDeviceDestroy,
    ]);
    krun::require(None, &symbols).context("failed to load libkrun symbols")?;

    Ok(())
}

fn krun_thread(
    args: &Args,
    display_backend_handle: DisplayBackendHandle,
    input_device_handles: Vec<InputBackendHandle>,
) -> anyhow::Result<()> {
    load_krun()?;

    let (target, level, style) = if let Some(path) = &args.color_log {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .context("Failed to open log output")?;
        let leaked_file: &'static File = Box::leak(Box::new(file));
        (
            Some(leaked_file.as_fd()),
            krun::LogLevel::Trace,
            krun::LogStyle::Always,
        )
    } else {
        (None, krun::LogLevel::Warn, krun::LogStyle::Auto)
    };

    krun::init_log(target, level, style, krun::LogOptions::empty())
        .map_err(|e| anyhow::anyhow!("init_log: {e}"))?;

    let root_dir = args
        .root_dir
        .to_str()
        .context("root_dir must be valid UTF-8")?;
    let mut rootfs = krun::FsDevice::new("/dev/root", root_dir)
        .map_err(|e| anyhow::anyhow!("FsDevice::new: {e}"))?;

    let mut payload =
        krun::Payload::load_krunfw().map_err(|e| anyhow::anyhow!("load_krunfw: {e}"))?;

    // Build init configuration.
    let exec = args.executable.as_ref().unwrap().to_str().unwrap();
    let argv_strs: Vec<&str> = args.argv.iter().map(|a| a.to_str().unwrap()).collect();
    let mut full_argv: Vec<&str> = vec![exec];
    full_argv.extend_from_slice(&argv_strs);
    let init_config = krun_init::Config::builder().args(&full_argv).build();
    let mut overlay = krun::FsOverlay::new();
    init_config
        .apply(&mut overlay, &mut payload)
        .map_err(|e| anyhow::anyhow!("Config::apply: {e}"))?;
    rootfs.set_overlay(overlay);

    let stdin = io::stdin();
    let stdout = io::stdout();
    let stderr = io::stderr();
    let mut console_builder = krun::ConsoleDevice::builder();
    console_builder
        .add_default_console(
            Some(stdin.as_fd()),
            Some(stdout.as_fd()),
            Some(stderr.as_fd()),
        )
        .map_err(|e| anyhow::anyhow!("add_default_console: {e}"))?;
    let console = console_builder
        .build()
        .map_err(|e| anyhow::anyhow!("ConsoleDevice::build: {e}"))?;

    let display_backend_vtable = display_backend_handle.get();
    let mut display_backend = krun::DisplayBackend::new(
        &raw const display_backend_vtable as *const std::ffi::c_void,
        std::mem::size_of_val(&display_backend_vtable),
    )
    .map_err(|e| anyhow::anyhow!("DisplayBackend::new: {e}"))?;

    for display in &args.display {
        let mut display_builder = krun::DisplayInfoBuilder::new(display.width, display.height);
        if let Some(refresh_rate) = display.refresh_rate {
            display_builder = display_builder.refresh_rate(refresh_rate);
        }
        display_builder = match display.physical_size {
            None => display_builder,
            Some(PhysicalSize::Dpi(dpi)) => display_builder.dpi(dpi),
            Some(PhysicalSize::DimensionsMillimeters(width_mm, height_mm)) => {
                display_builder.physical_size(width_mm, height_mm)
            }
        };
        display_backend.add_display(display_builder);
    }

    let input_files = args
        .input
        .iter()
        .map(|input| {
            File::open(input).with_context(|| format!("Failed to open input device {input:?}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut devices = krun::MmioDeviceManager::new();
    devices.add(rootfs);
    devices.add(console);

    #[cfg(target_os = "linux")]
    if let Some(socket_path) = &args.vhost_user_gpu {
        const VIRTIO_ID_GPU: u32 = 16;
        let queue_sizes = [1024u16; 2];
        let mut vhost_gpu = krun::VhostUserDevice::new(
            VIRTIO_ID_GPU,
            socket_path
                .to_str()
                .context("socket path must be valid UTF-8")?,
            "vhost-user-gpu",
            2,
            &queue_sizes,
        )
        .map_err(|e| anyhow::anyhow!("VhostUserDevice::new: {e}"))?;
        vhost_gpu.set_display_backend(display_backend);
        devices.add(vhost_gpu);
    } else {
        let gpu = krun::GpuDevice::new(
            VirglRendererFlags::USE_EGL
                | VirglRendererFlags::VENUS
                | VirglRendererFlags::RENDER_SERVER
                | VirglRendererFlags::THREAD_SYNC
                | VirglRendererFlags::USE_ASYNC_FENCE_CB,
            display_backend,
        );
        devices.add(gpu);
    }
    #[cfg(not(target_os = "linux"))]
    {
        if args.vhost_user_gpu.is_some() {
            anyhow::bail!("vhost-user-gpu is only supported on Linux");
        }
        let gpu = krun::GpuDevice::new(
            VirglRendererFlags::USE_EGL
                | VirglRendererFlags::VENUS
                | VirglRendererFlags::RENDER_SERVER
                | VirglRendererFlags::THREAD_SYNC
                | VirglRendererFlags::USE_ASYNC_FENCE_CB,
            display_backend,
        );
        devices.add(gpu);
    }

    for file in &input_files {
        let input_device = krun::InputDevice::new_from_fd(file.as_fd())
            .map_err(|e| anyhow::anyhow!("InputDevice::new_from_fd: {e}"))?;
        devices.add(input_device);
    }

    // Configure all input devices
    for handle in &input_device_handles {
        let config_backend = handle.get_config();
        let event_provider_backend = handle.get_events();

        let input_device = krun::InputDevice::new(
            &raw const config_backend as *const std::ffi::c_void,
            std::mem::size_of_val(&config_backend),
            &raw const event_provider_backend as *const std::ffi::c_void,
            std::mem::size_of_val(&event_provider_backend),
        )
        .map_err(|e| anyhow::anyhow!("InputDevice::new: {e}"))?;
        devices.add(input_device);
    }

    let vmm = krun::VmmBuilder::new()
        .vcpus(4)
        .map_err(|e| anyhow::anyhow!("vcpus: {e}"))?
        .ram_mib(4096)
        .map_err(|e| anyhow::anyhow!("ram_mib: {e}"))?
        .payload(payload)
        .devices(devices)
        .build()
        .map_err(|e| anyhow::anyhow!("VmmBuilder::build: {e}"))?;

    vmm.run();
    unreachable!("libkrun's VmmBuilder::run() should never return");
}

fn main() -> anyhow::Result<()> {
    env_logger::builder()
        .filter_level(LevelFilter::Debug)
        .init();
    let args = Args::parse();

    let mut per_display_inputs = vec![vec![]; args.display.len()];
    for (idx, display) in args.display.iter().enumerate() {
        if display.touch {
            per_display_inputs[idx].push(DisplayInputOptions::TouchScreen(TouchScreenOptions {
                // There is no specific reason for these axis sizes, just picked what my
                // physical hardware had
                area: TouchArea {
                    x: Axis {
                        max: 13764,
                        res: 40,
                        fuzz: 40,
                        ..Default::default()
                    },
                    y: Axis {
                        max: 7740,
                        res: 40,
                        fuzz: 40,
                        ..Default::default()
                    },
                },
                emit_mt: true,
                emit_non_mt: false,
                triggered_by_mouse: true,
                device_name: None,
            }));
        }
    }

    let (display_backend, input_backends, display_worker) = gtk_display::init(
        "libkrun examples/gui_vm".to_string(),
        args.keyboard_input,
        per_display_inputs,
    )?;

    thread::scope(|s| {
        s.spawn(|| {
            if let Err(e) = krun_thread(&args, display_backend, input_backends) {
                eprintln!("{e}");
                exit(1);
            }
        });
        display_worker.run()
    });
    unreachable!("Expected libkrun (or error handling) to exit the process");
}
