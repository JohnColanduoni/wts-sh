use std::{
    convert::TryInto,
    io::{self, Read, Write},
    mem, ptr,
    sync::Arc,
};

use tracing::{debug, trace_span};
use widestring::U16CString;
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, TRUE},
        winerror::{
            ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING, ERROR_PIPE_BUSY,
            ERROR_SUCCESS,
        },
    },
    um::{
        accctrl::{
            EXPLICIT_ACCESSW, NO_INHERITANCE, SET_ACCESS, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
            TRUSTEE_W,
        },
        aclapi::SetEntriesInAclW,
        fileapi::{CreateFileW, FlushFileBuffers, ReadFile, WriteFile, OPEN_EXISTING},
        ioapiset::GetOverlappedResultEx,
        minwinbase::{OVERLAPPED, SECURITY_ATTRIBUTES},
        namedpipeapi::{ConnectNamedPipe, CreateNamedPipeW, CreatePipe, SetNamedPipeHandleState},
        processthreadsapi::{GetCurrentProcess, OpenProcessToken},
        securitybaseapi::{
            GetTokenInformation, InitializeSecurityDescriptor, SetSecurityDescriptorDacl,
        },
        synchapi::CreateEventW,
        winbase::{
            LocalFree, FILE_FLAG_OVERLAPPED, INFINITE, PIPE_ACCESS_DUPLEX, PIPE_READMODE_BYTE,
            PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
        },
        winnt::{
            TokenUser, GENERIC_READ, GENERIC_WRITE, KEY_ALL_ACCESS, SECURITY_DESCRIPTOR_MIN_LENGTH,
            SECURITY_DESCRIPTOR_REVISION, TOKEN_INFORMATION_CLASS, TOKEN_READ, TOKEN_USER,
        },
    },
};
use winhandle::{
    macros::{GetLastError, INVALID_HANDLE_VALUE},
    WinHandle, WinHandleRef, WinHandleTarget,
};

pub struct ServerPipe {
    pipe: WinHandle,
}

pub struct Pipe {
    shared: Arc<_Pipe>,
    event: WinHandle,
}

pub struct _Pipe {
    pipe: WinHandle,
}

pub struct AnonPipe {
    pipe: WinHandle,
}

impl ServerPipe {
    pub fn new(name: &str) -> io::Result<ServerPipe> {
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

    pub fn accept(self) -> io::Result<Pipe> {
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
    pub fn copy(&self) -> io::Result<Pipe> {
        let shared = self.shared.clone();
        let event = create_event()?;
        Ok(Pipe { shared, event })
    }

    pub fn connect(pipe_name: &str) -> io::Result<Option<Pipe>> {
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
                if GetLastError() == ERROR_PIPE_BUSY {
                    return Ok(None);
                } else {
                    return Err(io::Error::last_os_error());
                }
            }
            let pipe = WinHandle::from_raw_unchecked(handle);

            let mut mode = PIPE_READMODE_BYTE;
            if SetNamedPipeHandleState(pipe.get(), &mut mode, ptr::null_mut(), ptr::null_mut())
                != TRUE
            {
                return Err(io::Error::last_os_error());
            }

            let event = create_event()?;

            Ok(Some(Pipe {
                shared: Arc::new(_Pipe { pipe }),
                event,
            }))
        }
    }

    pub fn handle(&self) -> &WinHandleRef {
        &self.shared.pipe
    }
}

impl AnonPipe {
    pub fn pair() -> io::Result<(AnonPipe, AnonPipe)> {
        unsafe {
            let mut pipe_read = ptr::null_mut();
            let mut pipe_write = ptr::null_mut();
            if CreatePipe(&mut pipe_read, &mut pipe_write, ptr::null_mut(), 0) == 0 {
                return Err(io::Error::last_os_error());
            }
            let pipe_read = AnonPipe {
                pipe: WinHandle::from_raw_unchecked(pipe_read),
            };
            let pipe_write = AnonPipe {
                pipe: WinHandle::from_raw_unchecked(pipe_write),
            };
            Ok((pipe_write, pipe_read))
        }
    }

    pub fn handle(&self) -> &WinHandleRef {
        &self.pipe
    }
}

impl Read for Pipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let span = trace_span!("Pipe::read", bytes_read = tracing::field::Empty);
        let _guard = span.enter();
        unsafe {
            let mut bytes_read: DWORD = 0;
            let mut overlapped: Box<OVERLAPPED> = Box::new(mem::zeroed());
            overlapped.hEvent = self.event.get();
            if ReadFile(
                self.shared.pipe.get(),
                buf.as_mut_ptr() as _,
                buf.len().try_into().expect("buffer too large"),
                &mut bytes_read,
                &mut *overlapped,
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
            span.record("bytes_read", &bytes_read);
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

impl Read for AnonPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let mut bytes_read: DWORD = 0;
            if ReadFile(
                self.pipe.get(),
                buf.as_mut_ptr() as _,
                buf.len().try_into().expect("buffer too large"),
                &mut bytes_read,
                ptr::null_mut(),
            ) != TRUE
            {
                let last_error = GetLastError();

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

impl Write for AnonPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let mut bytes_written: DWORD = 0;
            if WriteFile(
                self.pipe.get(),
                buf.as_ptr() as _,
                buf.len().try_into().expect("buffer too large"),
                &mut bytes_written,
                ptr::null_mut(),
            ) != TRUE
            {
                return Err(io::Error::last_os_error());
            }
            Ok(bytes_written as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        unsafe {
            if FlushFileBuffers(self.pipe.get()) != TRUE {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
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
