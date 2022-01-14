use std::os::windows::process::ExitStatusExt;
use std::process::ExitStatus;
use std::{convert::TryInto, ffi::OsStr, io, mem, path::Path, ptr};
use std::{os::windows::prelude::*, path::PathBuf};

use tracing::{debug_span, info, info_span};
use widestring::U16CString;
use winapi::um::processthreadsapi::GetExitCodeProcess;
use winapi::{
    shared::{
        basetsd::SIZE_T,
        minwindef::{DWORD, FALSE, TRUE},
    },
    um::{
        handleapi::CloseHandle,
        jobapi2::{AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject},
        processthreadsapi::{
            CreateProcessW, InitializeProcThreadAttributeList, ResumeThread,
            UpdateProcThreadAttribute, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_LIST,
        },
        synchapi::WaitForSingleObject,
        winbase::{
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
            STARTUPINFOEXW, WAIT_OBJECT_0,
        },
        wincontypes::HPCON,
        winnt::{
            JobObjectExtendedLimitInformation, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        },
    },
};
use winhandle::WinHandle;

pub struct Process {
    process_info: PROCESS_INFORMATION,
    _job_object: WinHandle,
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
}

impl Process {
    pub fn spawn<'a>(
        command_line: &str,
        attribute_list: &ProcThreadAttributeList,
        working_directory: &Path,
        environment: impl Iterator<Item = (&'a OsStr, &'a OsStr)>,
    ) -> io::Result<Process> {
        let span = info_span!("Process::spawn");
        let _guard = span.enter();
        unsafe {
            let command_line = U16CString::from_str(command_line).unwrap();
            let working_directory = U16CString::from_os_str(working_directory).unwrap();
            let mut environment_block: Vec<u16> = Vec::new();
            for (k, v) in environment {
                environment_block.extend(k.encode_wide());
                environment_block.push(b'=' as u16);
                environment_block.extend(v.encode_wide());
                environment_block.push(0);
            }
            environment_block.push(0);

            // Create a kill on close job object to ensure we don't leave zombie conhosts around
            let job_object = CreateJobObjectW(ptr::null_mut(), ptr::null());
            if job_object.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job_object = WinHandle::from_raw_unchecked(job_object);
            let mut job_info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = mem::zeroed();
            job_info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job_object.get(),
                JobObjectExtendedLimitInformation,
                &job_info as *const _ as _,
                mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
            ) != TRUE
            {
                return Err(io::Error::last_os_error());
            }

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
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                environment_block.as_ptr() as _,
                working_directory.as_ptr(),
                &mut startup_info as *mut STARTUPINFOEXW as _,
                &mut process_info,
            ) != TRUE
            {
                let err = io::Error::last_os_error();
                eprintln!("spawn failed: {:?}", err);
                return Err(err);
            }

            // Add to job object
            if AssignProcessToJobObject(job_object.get(), process_info.hProcess) != TRUE {
                return Err(io::Error::last_os_error());
            }

            // Now resume process
            if ResumeThread(process_info.hThread) == 0xFFFFFFFF {
                return Err(io::Error::last_os_error());
            }

            Ok(Process {
                process_info,
                _job_object: job_object,
            })
        }
    }

    pub fn wait(&mut self) -> io::Result<()> {
        let span = debug_span!("Process::wait");
        let _guard = span.enter();
        unsafe {
            if WaitForSingleObject(self.process_info.hProcess, INFINITE) != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            let mut exit_code_raw: DWORD = 0;
            if GetExitCodeProcess(self.process_info.hProcess, &mut exit_code_raw) == 0 {
                return Err(io::Error::last_os_error());
            }
            let exit_code = ExitStatus::from_raw(exit_code_raw);
            info!(
                exit_code = exit_code_raw,
                "process exited with code {}", exit_code
            );
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

            Ok(ProcThreadAttributeList { buffer })
        }
    }

    pub fn set_pseudoconsole(&mut self, pcon: HPCON) -> io::Result<()> {
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
