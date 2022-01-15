use std::{convert::TryInto, io, mem::MaybeUninit, ptr};

use tracing::debug_span;
use winapi::{
    shared::minwindef::{DWORD, TRUE},
    um::{
        consoleapi::{
            ClosePseudoConsole, CreatePseudoConsole, GetConsoleMode, GetNumberOfConsoleInputEvents,
            ReadConsoleInputW, ResizePseudoConsole, SetConsoleMode,
        },
        processenv::GetStdHandle,
        synchapi::WaitForMultipleObjects,
        winbase::{INFINITE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, WAIT_FAILED, WAIT_OBJECT_0},
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

use crate::synch::Interrupt;

pub struct Pty {
    pcon: HPCON,
}

unsafe impl Send for Pty {}
unsafe impl Sync for Pty {}

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

    pub fn resize(&self, width: u32, height: u32) -> io::Result<()> {
        unsafe {
            let result = ResizePseudoConsole(
                self.pcon,
                COORD {
                    X: width.try_into().unwrap(),
                    Y: height.try_into().unwrap(),
                },
            );
            if !SUCCEEDED(result) {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
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
        if SetConsoleMode(
            GetStdHandle(STD_OUTPUT_HANDLE),
            console_mode
                | ENABLE_PROCESSED_OUTPUT
                | DISABLE_NEWLINE_AUTO_RETURN
                | ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &mut console_mode);
        if SetConsoleMode(
            GetStdHandle(STD_INPUT_HANDLE),
            console_mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT)
                | ENABLE_WINDOW_INPUT
                | ENABLE_VIRTUAL_TERMINAL_INPUT,
        ) == 0
        {
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

pub fn wait_for_input_events_or_interrupt(event: &Interrupt) -> io::Result<Option<usize>> {
    const WAIT_OBJECT_1: u32 = WAIT_OBJECT_0 + 1;

    let span = debug_span!("wait_for_input_events_or_interrupt");
    let _guard = span.enter();

    unsafe {
        let input = GetStdHandle(STD_INPUT_HANDLE);
        let mut handles = [input, event.event().get()];
        loop {
            match WaitForMultipleObjects(
                handles.len().try_into().unwrap(),
                handles.as_mut_ptr(),
                0,
                INFINITE,
            ) {
                WAIT_OBJECT_0 => {
                    let mut event_count = 0;
                    if GetNumberOfConsoleInputEvents(input, &mut event_count) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    return Ok(Some(event_count as usize));
                }
                WAIT_OBJECT_1 => {
                    return Ok(None);
                }
                WAIT_FAILED => {
                    return Err(io::Error::last_os_error());
                }
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("invalid return value {other} from WaitForMultipleObjects"),
                    ));
                }
            }
        }
    }
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
