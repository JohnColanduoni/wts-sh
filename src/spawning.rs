use std::{convert::TryInto, io, ptr};

use widestring::U16CString;
use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, FALSE, TRUE},
    },
    um::{
        handleapi::CloseHandle,
        processthreadsapi::{
            CreateProcessW, InitializeProcThreadAttributeList, UpdateProcThreadAttribute,
            PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_LIST,
        },
        synchapi::WaitForSingleObject,
        winbase::{EXTENDED_STARTUPINFO_PRESENT, INFINITE, STARTUPINFOEXW, WAIT_OBJECT_0},
        wincontypes::HPCON,
    },
};

pub struct Process {
    process_info: PROCESS_INFORMATION,
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.process_info.hThread);
            CloseHandle(self.process_info.hProcess);
        }
    }
}

pub struct ProcThreadAttributeList {
    buffer: Vec<u8>,
    capacity: u32,
}

impl Process {
    pub fn spawn(
        command_line: &str,
        attribute_list: &ProcThreadAttributeList,
    ) -> io::Result<Process> {
        unsafe {
            let command_line = U16CString::from_str(command_line).unwrap();

            let mut startup_info: STARTUPINFOEXW = std::mem::zeroed();
            startup_info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as _;
            startup_info.lpAttributeList = attribute_list.ptr() as _;
            let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();
            if CreateProcessW(
                ptr::null(),
                command_line.as_ptr() as _,
                ptr::null_mut(),
                ptr::null_mut(),
                FALSE,
                EXTENDED_STARTUPINFO_PRESENT,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut startup_info as *mut STARTUPINFOEXW as _,
                &mut process_info,
            ) != TRUE
            {
                eprintln!("spawn failed");
                return Err(io::Error::last_os_error());
            }

            Ok(Process { process_info })
        }
    }

    pub fn wait(&mut self) -> io::Result<()> {
        unsafe {
            if WaitForSingleObject(self.process_info.hProcess, INFINITE) != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

impl ProcThreadAttributeList {
    pub fn new(capacity: usize) -> io::Result<ProcThreadAttributeList> {
        let capacity: u32 = capacity.try_into().unwrap();
        unsafe {
            let mut size: SIZE_T = 0;
            InitializeProcThreadAttributeList(ptr::null_mut(), capacity, 0, &mut size);
            let mut buffer: Vec<u8> = Vec::with_capacity(size);
            if InitializeProcThreadAttributeList(buffer.as_mut_ptr() as _, capacity, 0, &mut size)
                != TRUE
            {
                return Err(io::Error::last_os_error());
            }

            Ok(ProcThreadAttributeList { buffer, capacity })
        }
    }

    pub fn set_pseudoconsole(&mut self, index: usize, pcon: HPCON) -> io::Result<()> {
        unsafe {
            if UpdateProcThreadAttribute(
                self.buffer.as_mut_ptr() as _,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
                pcon as _,
                std::mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null_mut(),
            ) != TRUE
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    fn ptr(&self) -> *const PROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_ptr() as _
    }
}

const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE: SIZE_T = 0x00020016;
