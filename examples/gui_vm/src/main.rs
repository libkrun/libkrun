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
use std::sync::LazyLock;
use std::thread;

use anyhow::Context;
use krun::VirglRendererFlags;

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
}

/// Load libkrun (dlopen) and resolve the symbols this example needs.
fn load_krun() -> anyhow::Result<()> {
    let name = if cfg!(target_os = "macos") {
        "libkrun.dylib"
    } else {
        "libkrun.so"
    };
    unsafe {
        libloading::os::unix::Library::open(
            Some(name),
            libloading::os::unix::RTLD_NOW | libloading::os::unix::RTLD_GLOBAL,
        )
    }
    .with_context(|| format!("failed to dlopen {name}"))?;

    use krun::Symbol::*;
    krun::require(
        None,
        &[
            KrunInitLog,
            KrunMmioDeviceManagerNew,
            KrunMmioDeviceManagerAdd,
            KrunFsDeviceNew,
            KrunFsOverlayNew,
            KrunConsoleDeviceBuilder,
            KrunConsoleBuilderAddDefaultConsole,
            KrunConsoleBuilderBuild,
            KrunPayloadLoadKrunfw,
            KrunDisplayBackendNew,
            KrunDisplayInfoBuilderNew,
            KrunDisplayInfoBuilderDpi,
            KrunDisplayInfoBuilderPhysicalSize,
            KrunDisplayInfoBuilderRefreshRate,
            KrunGpuDeviceNew,
            KrunInputDeviceNew,
            KrunInputDeviceNewFromFd,
            KrunVmmBuilderNew,
            KrunVmmBuilderVcpus,
            KrunVmmBuilderRamMib,
            KrunVmmBuilderPayload,
            KrunVmmBuilderDevices,
            KrunVmmBuilderBuild,
            KrunVmmRun,
        ],
    )
    .context("failed to load libkrun symbols")?;

    Ok(())
}

fn krun_thread(
    args: &Args,
    display_backend_handle: DisplayBackendHandle,
    input_device_handles: Vec<InputBackendHandle>,
) -> anyhow::Result<()> {
    load_krun()?;

    krun::init_log(
        None,
        krun::LogLevel::Warn,
        krun::LogStyle::Auto,
        krun::LogOptions::empty(),
    )
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

    let mut console_builder = krun::ConsoleDevice::builder();
    console_builder
        .add_default_console(
            Some(
                io::stdin()
                    .as_fd()
                    .try_clone_to_owned()
                    .context("dup stdin")?,
            ),
            Some(
                io::stdout()
                    .as_fd()
                    .try_clone_to_owned()
                    .context("dup stdout")?,
            ),
            Some(
                io::stderr()
                    .as_fd()
                    .try_clone_to_owned()
                    .context("dup stderr")?,
            ),
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

    let gpu = krun::GpuDevice::new(
        VirglRendererFlags::USE_EGL
            | VirglRendererFlags::VENUS
            | VirglRendererFlags::RENDER_SERVER
            | VirglRendererFlags::THREAD_SYNC
            | VirglRendererFlags::USE_ASYNC_FENCE_CB,
        display_backend,
    );

    let mut devices = krun::MmioDeviceManager::new();
    devices.add(rootfs);
    devices.add(console);
    devices.add(gpu);

    for input in &args.input {
        let file =
            File::open(input).with_context(|| format!("Failed to open input device {input:?}"))?;
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
