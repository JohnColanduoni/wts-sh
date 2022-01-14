use std::{convert::TryInto, io, mem::MaybeUninit, ptr};

use winapi::{
    shared::minwindef::{DWORD, TRUE},
    um::{
        consoleapi::{
            ClosePseudoConsole, CreatePseudoConsole, GetConsoleMode, ReadConsoleInputW,
            SetConsoleMode,
        },
        processenv::GetStdHandle,
        winbase::{STD_INPUT_HANDLE, STD_OUTPUT_HANDLE},
        wincon::{
            GetConsoleScreenBufferInfo, CONSOLE_SCREEN_BUFFER_INFO, DISABLE_NEWLINE_AUTO_RETURN,
            ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT,
            ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, ENABLE_WINDOW_INPUT,
        },
        wincontypes::{
            COORD, FOCUS_EVENT, FOCUS_EVENT_RECORD, HPCON, INPUT_RECORD, KEY_EVENT,
            KEY_EVENT_RECORD, MENU_EVENT, MENU_EVENT_RECORD, MOUSE_EVENT, MOUSE_EVENT_RECORD,
            WINDOW_BUFFER_SIZE_EVENT, WINDOW_BUFFER_SIZE_RECORD,
        },
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
        Ok((
            (info.srWindow.Right - info.srWindow.Left + 1) as u32,
            (info.srWindow.Bottom - info.srWindow.Top + 1) as u32,
        ))
    }
}

pub fn enable_virtual_console() -> io::Result<()> {
    unsafe {
        let mut console_mode: DWORD = 0;
        GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mut console_mode);
        let hresult = SetConsoleMode(
            GetStdHandle(STD_OUTPUT_HANDLE),
            console_mode
                | ENABLE_PROCESSED_OUTPUT
                | DISABLE_NEWLINE_AUTO_RETURN
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        );
        if !SUCCEEDED(hresult) {
            return Err(io::Error::last_os_error());
        }
        GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut console_mode);
        let hresult = SetConsoleMode(
            GetStdHandle(STD_INPUT_HANDLE),
            console_mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
                | ENABLE_WINDOW_INPUT
                | ENABLE_VIRTUAL_TERMINAL_INPUT,
        );
        if !SUCCEEDED(hresult) {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

pub enum InputRecord<'a> {
    Key(&'a KEY_EVENT_RECORD),
    Mouse(&'a MOUSE_EVENT_RECORD),
    WindowBufferSize(&'a WINDOW_BUFFER_SIZE_RECORD),
    Menu(&'a MENU_EVENT_RECORD),
    Focus(&'a FOCUS_EVENT_RECORD),
}

pub struct RecordIter<'a> {
    raw: std::slice::Iter<'a, INPUT_RECORD>,
}

pub fn read_events(buffer: &mut [MaybeUninit<INPUT_RECORD>]) -> io::Result<RecordIter> {
    unsafe {
        let mut read_count: DWORD = 0;
        if ReadConsoleInputW(
            GetStdHandle(STD_INPUT_HANDLE),
            buffer.as_mut_ptr() as _,
            buffer.len().try_into().unwrap(),
            &mut read_count,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(RecordIter {
            raw: MaybeUninit::slice_assume_init_ref(&buffer[..(read_count as usize)]).iter(),
        })
    }
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = InputRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let raw = self.raw.next()?;
        Some(InputRecord::from_raw(raw))
    }
}

impl<'a> InputRecord<'a> {
    fn from_raw(record: &'a INPUT_RECORD) -> Self {
        unsafe {
            match record.EventType {
                KEY_EVENT => InputRecord::Key(record.Event.KeyEvent()),
                MOUSE_EVENT => InputRecord::Mouse(record.Event.MouseEvent()),
                WINDOW_BUFFER_SIZE_EVENT => {
                    InputRecord::WindowBufferSize(record.Event.WindowBufferSizeEvent())
                }
                MENU_EVENT => InputRecord::Menu(record.Event.MenuEvent()),
                FOCUS_EVENT => InputRecord::Focus(record.Event.FocusEvent()),
                _ => panic!("unsupported input record type"),
            }
        }
    }
}
