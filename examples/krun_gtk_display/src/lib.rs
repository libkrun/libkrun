mod display_backend;
mod display_worker;
mod input_backend;
mod input_constants;
mod scanout_paintable;

use crate::display_worker::DisplayWorker;
use crate::input_backend::{GtkInputEventProvider, GtkKeyboardConfig, GtkTouchscreenConfig};
use anyhow::Context;
pub use display_backend::DisplayEvent;
pub use display_backend::GtkDisplayBackend;
use krun_display::{DisplayBackend, IntoDisplayBackend};
use krun_input::{InputAbsInfo, InputConfigBackend, InputEventProviderBackend};
use krun_input::{InputEvent, IntoInputConfig, IntoInputEvents};
use utils::pollable_channel::{PollableChannelReciever, PollableChannelSender, pollable_channel};

pub struct DisplayBackendHandle {
    tx: PollableChannelSender<DisplayEvent>,
}

impl DisplayBackendHandle {
    pub fn get(&self) -> DisplayBackend<'_> {
        GtkDisplayBackend::into_display_backend(Some(&self.tx))
    }
}

pub enum InputBackendHandleConfig {
    Keyboard,
    TouchScreen(TouchScreenOptions),
}

pub struct InputBackendHandle {
    rx: PollableChannelReciever<InputEvent>,
    input_config: InputBackendHandleConfig,
}

impl InputBackendHandle {
    fn new(rx: PollableChannelReciever<InputEvent>, device_type: InputBackendHandleConfig) -> Self {
        Self {
            rx,
            input_config: device_type,
        }
    }

    pub fn get_events(&self) -> InputEventProviderBackend<'_> {
        GtkInputEventProvider::into_input_events(Some(&self.rx))
    }

    pub fn get_config(&self) -> InputConfigBackend<'_> {
        match self.input_config {
            InputBackendHandleConfig::Keyboard => GtkKeyboardConfig::into_input_config(None),
            InputBackendHandleConfig::TouchScreen(ref options) => {
                GtkTouchscreenConfig::into_input_config(Some(options))
            }
        }
    }
}

pub struct DisplayBackendWorker {
    app_name: String,
    display_rx: PollableChannelReciever<DisplayEvent>,
    keyboard_tx: Option<PollableChannelSender<InputEvent>>,
    per_display_inputs: Vec<Vec<(PollableChannelSender<InputEvent>, DisplayInputOptions)>>,
}

impl DisplayBackendWorker {
    /// NOTE: on macOS GTK has to run on the main thread of the application.
    pub fn run(self) {
        DisplayWorker::run(
            self.app_name,
            self.display_rx,
            self.keyboard_tx,
            self.per_display_inputs,
        );
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct Axis {
    pub min: u32,
    pub max: u32,
    pub res: u32,
    pub flat: u32,
    pub fuzz: u32,
}

impl From<Axis> for InputAbsInfo {
    fn from(val: Axis) -> Self {
        InputAbsInfo {
            min: val.min,
            max: val.max,
            fuzz: val.fuzz,
            flat: val.flat,
            res: val.res,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct TouchArea {
    pub x: Axis,
    pub y: Axis,
}

#[derive(Clone, Debug)]
pub struct TouchScreenOptions {
    /// Touchscreen area into which to map the events
    pub area: TouchArea,
    /// Enable emitting multitouch events
    pub emit_mt: bool,
    /// Enable emitting non-multitouch ABS_X/ABS_Y events (in addition to the multitouch events)
    pub emit_non_mt: bool,
    /// Translate mouse click & drag into touch events
    pub triggered_by_mouse: bool,
    /// Custom device name reported to the guest (defaults to "libkrun Touchscreen")
    pub device_name: Option<String>,
}

#[derive(Clone, Debug)]
pub enum DisplayInputOptions {
    TouchScreen(TouchScreenOptions),
}

/// Create gtk display and input backends
/// `per_display_inputs` is an array indexed by display id.
/// It contains inputs associated with that specific scanout
pub fn init(
    app_name: String,
    keyboard_input: bool,
    per_display_inputs: Vec<Vec<DisplayInputOptions>>,
) -> anyhow::Result<(
    DisplayBackendHandle,
    Vec<InputBackendHandle>,
    DisplayBackendWorker,
)> {
    let mut input_backend_handles =
        Vec::with_capacity(keyboard_input as usize + per_display_inputs.len());

    let mut keyboard_tx = None;
    if keyboard_input {
        let (tx, rx) = pollable_channel().context("Failed to create keyboard events channel")?;
        input_backend_handles.push(InputBackendHandle::new(
            rx,
            InputBackendHandleConfig::Keyboard,
        ));
        keyboard_tx = Some(tx);
    }

    let mut per_display_event_tx = Vec::with_capacity(per_display_inputs.len());

    for display_input_configs in per_display_inputs {
        let mut inputs = Vec::with_capacity(display_input_configs.len());

        for user_options in &display_input_configs {
            match user_options {
                DisplayInputOptions::TouchScreen(options) => {
                    let (tx, rx) = pollable_channel()
                        .context("Failed to create touchscreen events channel")?;
                    input_backend_handles.push(InputBackendHandle::new(
                        rx,
                        InputBackendHandleConfig::TouchScreen(options.clone()),
                    ));
                    inputs.push((tx, user_options.clone()))
                }
            }
        }
        per_display_event_tx.push(inputs);
    }

    let (display_tx, display_rx) =
        pollable_channel().context("Failed to create display events channel")?;
    let display_backend = DisplayBackendHandle { tx: display_tx };

    let worker = DisplayBackendWorker {
        app_name,
        display_rx,
        keyboard_tx,
        per_display_inputs: per_display_event_tx,
    };

    Ok((display_backend, input_backend_handles, worker))
}
