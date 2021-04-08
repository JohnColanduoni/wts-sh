mod spawning;

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
use spawning::{ProcThreadAttributeList, Process};
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

fn main() {
    let args: Vec<_> = env::args_os().collect();

    if args.get(1).map(|x| &**x) == Some(OsStr::new("--server")) {
        match server() {
            Ok(ret) => {
                std::process::exit(ret);
            }
            Err(err) => {
                panic!("error encountered: {}", err);
            }
        }
    }

    match client() {
        Ok(ret) => {
            std::process::exit(ret);
        }
        Err(err) => {
            panic!("error encountered: {}", err);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CommandSpec {
    command_line: String,
    console_width: u32,
    console_height: u32,
}

fn client() -> io::Result<i32> {
    let mut command_line = String::new();
    let mut first_arg = true;
    for arg in env::args_os().skip(1) {
        let arg_str = arg.to_str().expect("invalid unicode in argument");

        // FIXME: won't handle argument correctly
        if first_arg {
            first_arg = false;
        } else {
            command_line.push(' ');
        }

        command_line.push_str(arg_str);
    }

    let (console_width, console_height) = get_console_size()?;

    let command = CommandSpec {
        command_line,
        console_width,
        console_height,
    };

    let mut pipe = Pipe::connect(&pipe_name(1))?;

    let mut command_json = serde_json::to_string(&command).unwrap();
    command_json.push('\n');
    pipe.write(command_json.as_bytes())?;

    enable_virtual_console()?;

    let read_thread = std::thread::spawn({
        let mut pipe = pipe.copy()?;
        move || -> io::Result<()> {
            let mut stdout = stdout();
            loop {
                let mut buffer = [0u8; 4096];
                let bytes_read = pipe.read(&mut buffer)?;
                if bytes_read == 0 {
                    return Ok(());
                }
                stdout.write_all(&buffer[..bytes_read])?;
                stdout.flush()?;
            }
        }
    });

    let _write_thread = std::thread::spawn({
        let mut pipe = pipe.copy()?;
        move || -> io::Result<()> {
            let mut stdin = stdin();
            loop {
                let mut buffer = [0u8; 4096];
                let bytes_read = stdin.read(&mut buffer)?;
                if bytes_read == 0 {
                    return Ok(());
                }
                pipe.write_all(&buffer[..bytes_read])?;
                pipe.flush()?;
            }
        }
    });

    read_thread.join().unwrap()?;
    // We don't join the write thread since its blocked on stdin

    Ok(0)
}

fn server() -> io::Result<i32> {
    let session_id = get_current_session()?;

    if session_id == 0 {
        eprintln!("Attempted to launch server in session 0. This tool is designed to allow processes in session 0 to run processes in other sessions, not the reverse.");
        return Ok(1);
    }

    loop {
        let server_pipe = ServerPipe::new(&pipe_name(session_id))?;

        let pipe = server_pipe.accept()?;

        std::thread::spawn(move || {
            if let Err(err) = server_thread(pipe) {
                eprintln!("error servicing client: {}", err);
            }
        });
    }
}

fn server_thread(pipe: Pipe) -> io::Result<()> {
    let mut reader = BufReader::new(pipe.copy()?);

    let mut command_json = String::new();
    reader.read_line(&mut command_json)?;
    reader.into_inner();

    let command: CommandSpec =
        serde_json::from_str(&command_json).expect("failed to deserialize command");

    let pty = Pty::new(
        COORD {
            X: command
                .console_width
                .try_into()
                .expect("console width too large"),
            Y: command
                .console_height
                .try_into()
                .expect("console height too large"),
        },
        &pipe,
        PSEUDOCONSOLE_INHERIT_CURSOR,
    )?;

    let mut attribute_list = ProcThreadAttributeList::new(1)?;
    attribute_list.set_pseudoconsole(0, pty.pcon)?;
    let mut process = Process::spawn(&command.command_line, &attribute_list)?;

    process.wait()?;

    eprintln!("process exited");

    Ok(())
}

struct ServerPipe {
    pipe: WinHandle,
}

struct Pipe {
    shared: Arc<_Pipe>,
    event: WinHandle,
}

struct _Pipe {
    pipe: WinHandle,
}

struct Pty {
    pcon: HPCON,
}

impl Drop for Pty {
    fn drop(&mut self) {
        unsafe {
            ClosePseudoConsole(self.pcon);
        }
    }
}

impl ServerPipe {
    fn new(name: &str) -> io::Result<ServerPipe> {
        unsafe {
            // Get current user SID
            let current_token = current_process_token()?;
            let token_user = get_token_information(&current_token, TokenUser)?;
            let token_user = &*(token_user.as_ptr() as *const TOKEN_USER);

            // Create a security descriptor granting access to only the current user
            let mut security_descriptor = Vec::with_capacity(SECURITY_DESCRIPTOR_MIN_LENGTH);
            if InitializeSecurityDescriptor(
                security_descriptor.as_mut_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
            ) != TRUE
            {
                return Err(io::Error::last_os_error());
            }
            let mut explicit_access = EXPLICIT_ACCESSW {
                grfAccessPermissions: KEY_ALL_ACCESS,
                grfAccessMode: SET_ACCESS,
                grfInheritance: NO_INHERITANCE,
                Trustee: TRUSTEE_W {
                    TrusteeForm: TRUSTEE_IS_SID,
                    TrusteeType: TRUSTEE_IS_USER,
                    ptstrName: token_user.User.Sid as _,
                    pMultipleTrustee: ptr::null_mut(),
                    MultipleTrusteeOperation: 0,
                },
            };
            let mut acl = ptr::null_mut();
            match SetEntriesInAclW(1, &mut explicit_access, ptr::null_mut(), &mut acl) {
                ERROR_SUCCESS => {}
                err => return Err(io::Error::from_raw_os_error(err as _)),
            }
            if SetSecurityDescriptorDacl(security_descriptor.as_mut_ptr(), TRUE, acl, FALSE) != TRUE
            {
                return Err(io::Error::last_os_error());
            }

            let mut sec_attr = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as DWORD,
                bInheritHandle: FALSE,
                lpSecurityDescriptor: ptr::null_mut(),
            };
            let pipe_name = U16CString::from_str(name).unwrap();
            let handle = CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                0,
                0,
                0,
                &mut sec_attr,
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let pipe = WinHandle::from_raw_unchecked(handle);

            LocalFree(acl as _);

            Ok(ServerPipe { pipe })
        }
    }

    fn accept(self) -> io::Result<Pipe> {
        unsafe {
            if ConnectNamedPipe(self.pipe.get(), ptr::null_mut()) != TRUE {
                return Err(io::Error::last_os_error());
            }

            let mut mode = PIPE_READMODE_BYTE;
            if SetNamedPipeHandleState(self.pipe.get(), &mut mode, ptr::null_mut(), ptr::null_mut())
                != TRUE
            {
                return Err(io::Error::last_os_error());
            }

            let event = create_event()?;

            Ok(Pipe {
                shared: Arc::new(_Pipe { pipe: self.pipe }),
                event,
            })
        }
    }
}

impl Pipe {
    fn copy(&self) -> io::Result<Pipe> {
        let shared = self.shared.clone();
        let event = create_event()?;
        Ok(Pipe { shared, event })
    }

    fn connect(pipe_name: &str) -> io::Result<Pipe> {
        unsafe {
            let pipe_name = U16CString::from_str(pipe_name).unwrap();
            let handle = CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            );
            if handle == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let pipe = WinHandle::from_raw_unchecked(handle);

            let mut mode = PIPE_READMODE_BYTE;
            if SetNamedPipeHandleState(pipe.get(), &mut mode, ptr::null_mut(), ptr::null_mut())
                != TRUE
            {
                return Err(io::Error::last_os_error());
            }

            let event = create_event()?;

            Ok(Pipe {
                shared: Arc::new(_Pipe { pipe }),
                event,
            })
        }
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut bytes_read: DWORD = 0;
            let mut overlapped: Box<OVERLAPPED> = Box::new(mem::zeroed());
            overlapped.hEvent = self.event.get();
            if ReadFile(
                self.shared.pipe.get(),
                buf.as_mut_ptr() as _,
                buf.len().try_into().expect("buffer too large"),
                &mut bytes_read,
                ptr::null_mut(),
            ) != TRUE
            {
                let mut last_error = GetLastError();
                if last_error == ERROR_IO_PENDING {
                    if GetOverlappedResultEx(
                        self.shared.pipe.get(),
                        &mut *overlapped,
                        &mut bytes_read,
                        INFINITE,
                        FALSE,
                    ) == TRUE
                    {
                        return Ok(bytes_read as usize);
                    } else {
                        last_error = GetLastError();
                    }
                }

                if last_error == ERROR_BROKEN_PIPE {
                    // This is a normal EOF condition
                    return Ok(0);
                } else {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(bytes_read as usize)
        }
    }
}

impl Write for Pipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let mut bytes_written: DWORD = 0;
            let mut overlapped: Box<OVERLAPPED> = Box::new(mem::zeroed());
            overlapped.hEvent = self.event.get();
            if WriteFile(
                self.shared.pipe.get(),
                buf.as_ptr() as _,
                buf.len().try_into().expect("buffer too large"),
                &mut bytes_written,
                &mut *overlapped,
            ) != TRUE
            {
                if GetLastError() == ERROR_IO_PENDING {
                    if GetOverlappedResultEx(
                        self.shared.pipe.get(),
                        &mut *overlapped,
                        &mut bytes_written,
                        INFINITE,
                        FALSE,
                    ) != TRUE
                    {
                        return Err(io::Error::last_os_error());
                    }
                } else {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(bytes_written as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        unsafe {
            if FlushFileBuffers(self.shared.pipe.get()) != TRUE {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

impl Pty {
    fn new(size: COORD, pipe: &Pipe, flags: DWORD) -> io::Result<Pty> {
        unsafe {
            let mut pcon: HPCON = ptr::null_mut();
            let result = CreatePseudoConsole(
                size,
                pipe.shared.pipe.get(),
                pipe.shared.pipe.get(),
                flags,
                &mut pcon,
            );
            if !SUCCEEDED(result) {
                return Err(io::Error::last_os_error());
            }
            Ok(Pty { pcon })
        }
    }
}

fn get_console_size() -> io::Result<(u32, u32)> {
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

fn enable_virtual_console() -> io::Result<()> {
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

fn pipe_name(session_id: DWORD) -> String {
    format!(r#"\??\GLOBAL\pipe\Global\WtsSh.{}"#, session_id)
}

fn create_event() -> io::Result<WinHandle> {
    unsafe {
        let handle = CreateEventW(ptr::null_mut(), TRUE, FALSE, ptr::null());
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        Ok(WinHandle::from_raw_unchecked(handle))
    }
}

fn get_current_session() -> io::Result<DWORD> {
    unsafe {
        let mut session_id: DWORD = 0;
        if ProcessIdToSessionId(GetCurrentProcessId(), &mut session_id) != TRUE {
            return Err(io::Error::last_os_error());
        }
        Ok(session_id)
    }
}

fn current_process_token() -> io::Result<WinHandle> {
    unsafe {
        let mut target = WinHandleTarget::new();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_READ, &mut *target) != TRUE {
            return Err(io::Error::last_os_error());
        }
        Ok(target.unwrap())
    }
}

fn get_token_information(
    handle: &WinHandleRef,
    class: TOKEN_INFORMATION_CLASS,
) -> io::Result<Vec<u8>> {
    unsafe {
        let mut length: DWORD = 0;
        if GetTokenInformation(handle.get(), class, ptr::null_mut(), 0, &mut length) != TRUE {
            if GetLastError() == ERROR_INSUFFICIENT_BUFFER {
                // Fine, expected
            } else {
                return Err(io::Error::last_os_error());
            }
        }
        let mut buffer = Vec::with_capacity(length as usize);
        if GetTokenInformation(
            handle.get(),
            class,
            buffer.as_mut_ptr() as _,
            buffer.capacity() as DWORD,
            &mut length,
        ) != TRUE
        {
            return Err(io::Error::last_os_error());
        }
        buffer.set_len(length as usize);

        Ok(buffer)
    }
}

const PSEUDOCONSOLE_INHERIT_CURSOR: DWORD = 1;
