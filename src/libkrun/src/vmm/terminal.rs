#[cfg(unix)]
use nix::sys::termios::{LocalFlags, SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr};
#[cfg(unix)]
use std::os::fd::BorrowedFd;

#[cfg(windows)]
use std::{
    io,
    os::windows::io::{AsRawHandle, BorrowedHandle},
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    CONSOLE_MODE, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
    ENABLE_VIRTUAL_TERMINAL_INPUT, GetConsoleMode, SetConsoleMode,
};
#[must_use]
#[cfg(unix)]
pub struct TerminalMode(Termios);

#[must_use]
#[cfg(windows)]
pub struct TerminalMode(CONSOLE_MODE);

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

    mode |= ENABLE_VIRTUAL_TERMINAL_INPUT;

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
