mod console;
mod pipe;
mod spawning;

use std::{
    convert::TryInto,
    env,
    ffi::OsStr,
    io::{self, stdin, stdout, BufRead, BufReader, Read, Write},
};

use serde::{Deserialize, Serialize};
use winapi::{
    shared::minwindef::{DWORD, TRUE},
    um::{
        processthreadsapi::{GetCurrentProcessId, ProcessIdToSessionId},
        wincontypes::COORD,
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
        pipe.handle(),
        pipe.handle(),
        PSEUDOCONSOLE_INHERIT_CURSOR,
    )?;

    let mut attribute_list = ProcThreadAttributeList::new(1)?;
    attribute_list.set_pseudoconsole(pty.pcon())?;
    let mut process = Process::spawn(&command.command_line, &attribute_list)?;

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

const PSEUDOCONSOLE_INHERIT_CURSOR: DWORD = 1;
