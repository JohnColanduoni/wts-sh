#![feature(maybe_uninit_slice, maybe_uninit_uninit_array)]

mod console;
mod pipe;
mod spawning;

use std::{
    convert::TryInto,
    env,
    ffi::{OsStr, OsString},
    io::{self, stdin, stdout, BufRead, BufReader, Read, Write},
    mem::{self, MaybeUninit},
    path::PathBuf,
};

use console::{read_events, InputRecord};
use serde::{Deserialize, Serialize};
use winapi::{
    shared::minwindef::{DWORD, TRUE},
    um::{
        processthreadsapi::{GetCurrentProcessId, ProcessIdToSessionId},
        wincontypes::{COORD, INPUT_RECORD},
    },
};

use crate::console::{enable_virtual_console, get_console_size, Pty};
use crate::pipe::{Pipe, ServerPipe};
use crate::spawning::{ProcThreadAttributeList, Process};

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

#[derive(Serialize, Deserialize, Debug)]
struct CommandSpec {
    command_line: String,
    console_width: u32,
    console_height: u32,
    working_directory: PathBuf,
    environment: Vec<(OsString, OsString)>,
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
        working_directory: std::env::current_dir().unwrap(),
        environment: std::env::vars_os().collect(),
    };

    let mut pipe = if let Some(pipe) = Pipe::connect(&pipe_name(1))? {
        pipe
    } else {
        eprintln!("a wts-sh server does not appear to be running");
        return Ok(1);
    };

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
            let mut buffer: [MaybeUninit<INPUT_RECORD>; 1024] = MaybeUninit::uninit_array();
            let mut output_code_units: Vec<u16> = Vec::new();
            let mut output_bytes = Vec::new();
            loop {
                for event in read_events(&mut buffer)? {
                    match event {
                        InputRecord::Key(key) => {
                            let uchar = unsafe { *key.uChar.UnicodeChar() };
                            if key.bKeyDown != 0 {
                                output_code_units.push(uchar);
                            }
                        }
                        InputRecord::Mouse(_) => todo!(),
                        InputRecord::WindowBufferSize(_) => todo!(),
                        InputRecord::Menu(_) => todo!(),
                        InputRecord::Focus(_) => todo!(),
                    }
                }

                if &*output_code_units == &[0x1B] {
                    // ConPTY doesn't handle isolated ESC bytes correctly
                    // TODO: fix this for e.g. VI
                    output_code_units.clear();
                    continue;
                }

                let mut chars = char::decode_utf16(output_code_units.iter().cloned());
                output_bytes.clear();
                loop {
                    match chars.next() {
                        Some(Ok(c)) => {
                            let mut utf8_buf = [0u8; 4];
                            output_bytes.extend_from_slice(c.encode_utf8(&mut utf8_buf).as_bytes());
                        }
                        Some(Err(_)) => {
                            if chars.next().is_some() {
                                panic!("bad UTF-16");
                            } else {
                                // Leftover partial surrogate, leave in array
                                output_code_units.drain(..(output_code_units.len() - 1));
                                break;
                            }
                        }
                        None => {
                            // All code units processed
                            output_code_units.clear();
                            break;
                        }
                    }
                }

                if !output_bytes.is_empty() {
                    pipe.write_all(&output_bytes)?;
                }
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
        pipe.handle(),
        pipe.handle(),
        0,
    )?;

    let mut attribute_list = ProcThreadAttributeList::new(1)?;
    attribute_list.set_pseudoconsole(pty.pcon())?;
    let mut process = Process::spawn(
        &command.command_line,
        &attribute_list,
        &command.working_directory,
        command.environment.iter().map(|(k, v)| (&**k, &**v)),
    )?;

    process.wait()?;

    eprintln!("process exited");

    Ok(())
}

fn pipe_name(session_id: DWORD) -> String {
    // Ensure we use pipe in the global namespace, as we want access from different sessions to be possible
    format!(r#"\??\GLOBAL\pipe\Global\WtsSh.{}"#, session_id)
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
