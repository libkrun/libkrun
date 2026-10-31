#[cfg(unix)]
use nix::sys::termios::{LocalFlags, SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};
#[cfg(unix)]
use std::os::fd::BorrowedFd;

#[cfg(windows)]
use std::sync::{LazyLock, Mutex};
#[cfg(windows)]
use std::{
    io,
    os::windows::io::{AsRawHandle, BorrowedHandle},
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, GetConsoleOutputCP, SetConsoleMode,
    SetConsoleOutputCP,
};
#[must_use]
#[cfg(unix)]
pub struct TerminalMode(Termios);

#[must_use]
#[cfg(windows)]
pub struct TerminalMode(CONSOLE_MODE);

#[must_use]
#[cfg(windows)]
pub struct ConsoleOutputCodePage(u32);

#[cfg(windows)]
const UTF8_CODE_PAGE: u32 = 65001;

#[cfg(windows)]
#[derive(Default)]
struct ConsoleOutputState {
    users: usize,
    restore: Option<ConsoleOutputCodePage>,
}

#[cfg(windows)]
static CONSOLE_OUTPUT_STATE: LazyLock<Mutex<ConsoleOutputState>> =
    // The console output code page is process-global, so concurrent VMMs must
    // share ownership to avoid restoring it while another VMM still uses it.
    LazyLock::new(|| Mutex::new(ConsoleOutputState::default()));

#[cfg(windows)]
pub struct ConsoleOutputGuard {
    active: bool,
}

#[cfg(unix)]
pub fn term_set_raw_mode(
    term: BorrowedFd,
    handle_signals_by_terminal: bool,
) -> Result<TerminalMode, nix::Error> {
    let mut termios = tcgetattr(term)?;
    let old_state = termios.clone();

    cfmakeraw(&mut termios);

    if handle_signals_by_terminal {
        termios.local_flags |= LocalFlags::ISIG;
    }

    tcsetattr(term, SetArg::TCSANOW, &termios)?;
    Ok(TerminalMode(old_state))
}

#[cfg(unix)]
pub fn term_restore_mode(term: BorrowedFd, restore: &TerminalMode) -> Result<(), nix::Error> {
    tcsetattr(term, SetArg::TCSANOW, &restore.0)
}

#[cfg(windows)]
pub fn term_set_raw_mode(
    term: BorrowedHandle<'_>,
    handle_signals_by_terminal: bool,
    enable_vt_translation: bool,
) -> Result<TerminalMode, io::Error> {
    let mut mode: CONSOLE_MODE = 0;

    let ret = unsafe { GetConsoleMode(term.as_raw_handle(), &mut mode) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    let old_state = mode;

    mode &= !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT);

    if handle_signals_by_terminal {
        mode |= ENABLE_PROCESSED_INPUT;
    } else {
        mode &= !ENABLE_PROCESSED_INPUT;
    }

    if enable_vt_translation {
        mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;
    } else {
        mode &= !ENABLE_VIRTUAL_TERMINAL_INPUT;
    }

    let ret = unsafe { SetConsoleMode(term.as_raw_handle(), mode) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(TerminalMode(old_state))
}

#[cfg(windows)]
pub fn term_restore_mode(
    term: BorrowedHandle<'_>,
    restore: &TerminalMode,
) -> Result<(), io::Error> {
    let ret = unsafe { SetConsoleMode(term.as_raw_handle(), restore.0) };
    if ret == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(windows)]
pub fn term_acquire_utf8_output() -> Result<ConsoleOutputGuard, io::Error> {
    let mut state = CONSOLE_OUTPUT_STATE.lock().unwrap();
    if state.users == 0 {
        let old_code_page = unsafe { GetConsoleOutputCP() };
        if old_code_page == 0 {
            return Err(io::Error::last_os_error());
        }
        if old_code_page != UTF8_CODE_PAGE {
            if unsafe { SetConsoleOutputCP(UTF8_CODE_PAGE) } == 0 {
                return Err(io::Error::last_os_error());
            }
            state.restore = Some(ConsoleOutputCodePage(old_code_page));
        }
    }
    state.users += 1;
    Ok(ConsoleOutputGuard { active: true })
}

#[cfg(windows)]
impl ConsoleOutputGuard {
    pub fn release(&mut self) -> Result<(), io::Error> {
        if !self.active {
            return Ok(());
        }
        self.active = false;

        let mut state = CONSOLE_OUTPUT_STATE.lock().unwrap();
        state.users -= 1;
        if state.users == 0
            && let Some(restore) = state.restore.take()
            && unsafe { SetConsoleOutputCP(restore.0) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for ConsoleOutputGuard {
    fn drop(&mut self) {
        if let Err(e) = self.release() {
            log::error!("Failed to restore terminal output code page: {e}");
        }
    }
}
