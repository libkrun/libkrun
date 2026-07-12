use clap::Parser;
use clap_derive::Parser;
use gtk_display::{
    Axis, DisplayBackendHandle, DisplayInputOptions, InputBackendHandle, TouchArea,
    TouchScreenOptions,
};

use krun_sys::{
    KRUN_LOG_LEVEL_TRACE, KRUN_LOG_LEVEL_WARN, KRUN_LOG_STYLE_ALWAYS, KRUN_LOG_TARGET_DEFAULT,
    VIRGLRENDERER_RENDER_SERVER, VIRGLRENDERER_THREAD_SYNC, VIRGLRENDERER_USE_ASYNC_FENCE_CB,
    VIRGLRENDERER_USE_EGL, VIRGLRENDERER_VENUS, krun_add_display, krun_add_input_device,
    krun_add_input_device_fd, krun_add_virtio_console_default, krun_add_virtiofs3, krun_create_ctx,
    krun_display_set_dpi, krun_display_set_physical_size, krun_display_set_refresh_rate,
    krun_init_log, krun_set_display_backend, krun_set_gpu_options2, krun_set_vm_config,
    krun_start_enter,
};
use log::LevelFilter;
use regex::{Captures, Regex};
use std::ffi::{CString, c_void};
use std::fmt::Display;
use std::fs::{File, OpenOptions};
use std::mem::size_of_val;

use anyhow::Context;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::path::PathBuf;
use std::process::exit;
use std::str::FromStr;
use std::sync::LazyLock;
use std::thread;

mod krun_utils;

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

fn krun_thread(
    args: &Args,
    display_backend_handle: DisplayBackendHandle,
    input_device_handles: Vec<InputBackendHandle>,
) -> anyhow::Result<()> {
    unsafe {
        if let Some(path) = &args.color_log {
            krun_call!(krun_init_log(
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .context("Failed to open log output")?
                    .into_raw_fd(),
                KRUN_LOG_LEVEL_TRACE,
                KRUN_LOG_STYLE_ALWAYS,
                0
            ))?;
        } else {
            krun_call!(krun_init_log(
                KRUN_LOG_TARGET_DEFAULT,
                KRUN_LOG_LEVEL_WARN,
                0,
                0,
            ))?;
        }

        let ctx = krun_call_u32!(krun_create_ctx())?;

        krun_call!(krun_set_vm_config(ctx, 4, 4096))?;

        krun_call!(krun_add_virtio_console_default(
            ctx,
            std::io::stdin().as_raw_fd(),
            std::io::stdout().as_raw_fd(),
            std::io::stderr().as_raw_fd(),
        ))?;

        krun_call!(krun_set_gpu_options2(
            ctx,
            VIRGLRENDERER_USE_EGL
                | VIRGLRENDERER_VENUS
                | VIRGLRENDERER_RENDER_SERVER
                | VIRGLRENDERER_THREAD_SYNC
                | VIRGLRENDERER_USE_ASYNC_FENCE_CB,
            4096
        ))?;

        krun_call!(krun_add_virtiofs3(
            ctx,
            c"/dev/root".as_ptr(),
            args.root_dir.as_ptr(),
            0,
            false
        ))?;

        // Build init configuration.
        let exec = args.executable.as_ref().unwrap().to_str().unwrap();
        let argv_strs: Vec<&str> = args.argv.iter().map(|a| a.to_str().unwrap()).collect();
        let mut full_argv: Vec<&str> = vec![exec];
        full_argv.extend_from_slice(&argv_strs);
        let init_config = krun_init::Config::builder().args(&full_argv).build();
        init_config
            .apply(std::ptr::null_mut(), ctx, "/dev/root")
            .expect("apply init config");

        for display in &args.display {
            let display_id = krun_call_u32!(krun_add_display(ctx, display.width, display.height))?;
            if let Some(refresh_rate) = display.refresh_rate {
                krun_call!(krun_display_set_refresh_rate(ctx, display_id, refresh_rate))?;
            }
            match display.physical_size {
                None => (),
                Some(PhysicalSize::Dpi(dpi)) => {
                    krun_call!(krun_display_set_dpi(ctx, display_id, dpi))?;
                }
                Some(PhysicalSize::DimensionsMillimeters(width_mm, height_mm)) => {
                    krun_call!(krun_display_set_physical_size(
                        ctx, display_id, width_mm, height_mm
                    ))?;
                }
            };
        }
        let display_backend = display_backend_handle.get();
        krun_call!(krun_set_display_backend(
            ctx,
            &raw const display_backend as *const c_void,
            size_of_val(&display_backend),
        ))?;

        for input in &args.input {
            let fd = File::open(input)
                .with_context(|| format!("Failed to open input device {input:?}"))?
                .into_raw_fd();
            krun_call!(krun_add_input_device_fd(ctx, fd))
                .context("Failed to attach input device")?;
        }

        // Configure all input devices
        for handle in &input_device_handles {
            let config_backend = handle.get_config();
            let event_provider_backend = handle.get_events();

            krun_call!(krun_add_input_device(
                ctx,
                &raw const config_backend as *const c_void,
                size_of_val(&config_backend),
                &raw const event_provider_backend as *const c_void,
                size_of_val(&event_provider_backend),
            ))?;
        }

        krun_call!(krun_start_enter(ctx))?;
    };
    Ok(())
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
