use std::{
    convert::TryInto,
    env,
    ffi::OsStr,
    io::{self, stdin, stdout, BufRead, BufReader, Read, Write},
    mem, ptr,
    sync::Arc,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use widestring::U16CString;
use winapi::{
    shared::{
        minwindef::{BOOL, DWORD, FALSE, TRUE},
        winerror::{ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_SUCCESS},
    },
    um::{
        accctrl::{
            EXPLICIT_ACCESSW, NO_INHERITANCE, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
            TRUSTEE_W,
        },
        aclapi::SetEntriesInAclW,
        consoleapi::{ClosePseudoConsole, CreatePseudoConsole, GetConsoleMode, SetConsoleMode},
        fileapi::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile, OPEN_EXISTING},
        ioapiset::GetOverlappedResultEx,
        minwinbase::{LPOVERLAPPED, OVERLAPPED, SECURITY_ATTRIBUTES},
        namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, CreatePipe, SetNamedPipeHandleState},
        processenv::GetStdHandle,
        processthreadsapi::{
            GetCurrentProcess, GetCurrentProcessId, InitializeProcThreadAttributeList,
            OpenProcessToken, ProcessIdToSessionId,
        },
        securitybaseapi::{
            GetTokenInformation, InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
        },
        synchapi::{CreateEventW, WaitForSingleObject},
        winbase::{
            LocalFree, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
            FILE_FLAG_WRITE_THROUGH, INFINITE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE,
            PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_TYPE_MESSAGE,
            PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
            WAIT_OBJECT_0,
        },
        wincon::{
            GetConsoleScreenBufferInfo, CONSOLE_SCREEN_BUFFER_INFO, ENABLE_ECHO_INPUT,
            ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT, ENABLE_PROCESSED_OUTPUT,
            ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        },
        wincontypes::{COORD, HPCON},
        winnt::{
            TokenUser, GENERIC_READ, GENERIC_WRITE, HANDLE, KEY_ALL_ACCESS,
            SECURITY_DESCRIPTOR_MIN_LENGTH, SECURITY_DESCRIPTOR_REVISION, TOKEN_INFORMATION_CLASS,
            TOKEN_READ, TOKEN_USER,
        },
    },
};
use winhandle::{
    macros::{GetLastError, INVALID_HANDLE_VALUE, SUCCEEDED},
    WinHandle, WinHandleRef, WinHandleTarget,
};

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
