use std::{io, ptr};

use winapi::{
    shared::minwindef::{DWORD, TRUE},
    um::{
        consoleapi::{ClosePseudoConsole, CreatePseudoConsole, GetConsoleMode, SetConsoleMode},
        processenv::GetStdHandle,
        winbase::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        wincon::{
            GetConsoleScreenBufferInfo, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT,
            ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT,
            ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        },
        wincontypes::{COORD, HPCON},
    },
};
use winhandle::{macros::SUCCEEDED, WinHandleRef};

pub struct Pty {
    pcon: HPCON,
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            ClosePseudoConsole(self.pcon);
        }
    }
}

impl Pty {
    pub fn new(
        size: COORD,
        input: &WinHandleRef,
        output: &WinHandleRef,
        flags: DWORD,
    ) -> io::Result<Pty> {
        unsafe {
            let mut pcon: HPCON = ptr::null_mut();
            let result = CreatePseudoConsole(size, input.get(), output.get(), flags, &mut pcon);
            if !SUCCEEDED(result) {
                return Err(io::Error::last_os_error());
            }
            Ok(Pty { pcon })
        }
    }

    pub fn pcon(&self) -> HPCON {
        self.pcon
    }
}

pub fn get_console_size() -> io::Result<(u32, u32)> {
    unsafe {
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) != TRUE {
            return Err(io::Error::last_os_error());
        }
        Ok((info.dwSize.X as u32, info.dwSize.Y as u32))
    }
}

pub fn enable_virtual_console() -> io::Result<()> {
    unsafe {
        let mut console_mode: DWORD = 0;
        GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut console_mode);
        let hresult = SetConsoleMode(
            GetStdHandle(STD_OUTPUT_HANDLE),
            console_mode | ENABLE_PROCESSED_OUTPUT | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        );
        if !SUCCEEDED(hresult) {
            return Err(io::Error::last_os_error());
        }
        let hresult = SetConsoleMode(
            GetStdHandle(STD_INPUT_HANDLE),
            console_mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
                | ENABLE_VIRTUAL_TERMINAL_INPUT,
        );
        if !SUCCEEDED(hresult) {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
