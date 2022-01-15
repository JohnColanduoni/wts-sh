use std::{io, ptr};

use winapi::shared::minwindef::{FALSE, TRUE};
use winapi::um::synchapi::{CreateEventW, SetEvent};
use winhandle::{WinHandle, WinHandleRef};

pub struct Interrupt {
    event: WinHandle,
}

impl Interrupt {
    pub fn new() -> io::Result<Interrupt> {
        unsafe {
            let handle = CreateEventW(ptr::null_mut(), TRUE, FALSE, ptr::null_mut());
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            Ok(Interrupt {
                event: WinHandle::from_raw_unchecked(handle),
            })
        }
    }

    pub fn interrupt(&self) -> io::Result<()> {
        unsafe {
            if SetEvent(self.event.get()) == FALSE {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }

    #[inline]
    pub(crate) fn event(&self) -> &WinHandleRef {
        &self.event
    }
}
