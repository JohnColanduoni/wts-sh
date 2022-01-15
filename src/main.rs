#![feature(maybe_uninit_slice, maybe_uninit_uninit_array)]
#![feature(box_patterns)]

mod console;
mod pipe;
mod spawning;
mod synch;

use std::{
    borrow::Cow,
    convert::TryInto,
    env,
    ffi::{OsStr, OsString},
    fs,
    io::{self, stdout, Read, Write},
    mem::MaybeUninit,
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use console::{read_events, wait_for_input_events_or_interrupt, InputRecord};
use serde::{Deserialize, Serialize};
use synch::Interrupt;
use tracing::{debug, debug_span, info, info_span, trace, trace_span};
use tracing_subscriber::{fmt::format::FmtSpan, EnvFilter};
use winapi::{
    shared::minwindef::{DWORD, TRUE},
    um::{
        processthreadsapi::{GetCurrentProcessId, ProcessIdToSessionId},
        wincontypes::{COORD, INPUT_RECORD},
    },
};

use crate::pipe::{Pipe, ServerPipe};
use crate::spawning::{ProcThreadAttributeList, Process};
use crate::{
    console::{enable_virtual_console, get_console_size, Pty},
    pipe::AnonPipe,
};

#[derive(Parser, Debug)]
struct Options {
    #[clap(long)]
    server: bool,

    #[clap(long)]
    socket_name: Option<String>,

    #[clap(long)]
    log_file: Option<PathBuf>,
}

fn main() {
    let (options, command) = parse_args();

    if options.server {
        if !command.is_empty() {
            eprintln!("unexpected command arguments for server");
            std::process::exit(2);
        }

        match server(&options) {
            Ok(ret) => {
                std::process::exit(ret);
            }
            Err(err) => {
                panic!("error encountered: {}", err);
            }
        }
    }

    match client(&options, &command) {
        Ok(ret) => {
            std::process::exit(ret);
        }
        Err(err) => {
            panic!("error encountered: {}", err);
        }
    }
}

fn parse_args() -> (Options, Vec<OsString>) {
    let args: Vec<_> = env::args_os().collect();
    let mut last_error: Option<clap::Error> = None;
    // Try to parse as many arguments as flags as possible
    // Note that we don't go past 1, since that is the current executable name and clap always expects it
    for pivot in (1..=args.len()).rev() {
        let flags = &args[..pivot];
        let command = &args[pivot..];
        match Options::try_parse_from(flags) {
            Ok(options) => {
                // Check if first command argument is okay
                if command.first().map(|x| &**x) == Some(OsStr::new("--")) {
                    // Explicit command separator, skip it and accept whatever follows as the command
                    return (options, command[1..].to_vec());
                } else if command
                    .first()
                    .and_then(|x| x.to_str())
                    .map(|flag| flag.starts_with("--"))
                    .unwrap_or(false)
                {
                    // First command starts with `--`. This likely indicates an invalid flag, print last error
                    last_error.unwrap().exit();
                } else {
                    // First command argument doesn't look like a flag, we're good to go
                    return (options, command.to_vec());
                }
            }
            Err(error) => {
                last_error = Some(error);
            }
        }
    }
    // At the very least, a pivot of 0 should always work
    unreachable!()
}

#[derive(Serialize, Deserialize, Debug)]
struct CommandSpec {
    command_line: String,
    console_width: u32,
    console_height: u32,
    working_directory: PathBuf,
    environment: Vec<(OsString, OsString)>,
}

#[derive(Serialize, Deserialize, Debug)]
enum InputEvent<'a> {
    KeySequence { bytes: Cow<'a, [u8]> },
    Resize { width: u32, height: u32 },
}

#[derive(Serialize, Deserialize, Debug)]
enum OutputEvent<'a> {
    Output { bytes: Cow<'a, [u8]> },
    Exit { code: DWORD },
}

fn client(options: &Options, command: &[OsString]) -> io::Result<i32> {
    let _appender_guard;
    if let Some(log_filename) = &options.log_file {
        let log_file = fs::File::create(log_filename).expect("failed to open log file");
        let (non_blocking, _guard) = tracing_appender::non_blocking(log_file);
        tracing_subscriber::fmt()
            .with_writer(non_blocking)
            .with_env_filter(EnvFilter::from_default_env())
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_ansi(false)
            .init();
        _appender_guard = _guard;
    }

    let mut command_line = String::new();
    let mut first_arg = true;
    for arg in command {
        let arg_str = arg.to_str().expect("invalid unicode in argument");

        // FIXME: won't handle escaped argument correctly
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

    let mut pipe = if let Some(pipe) = Pipe::connect(&pipe_name(1, options.socket_name.as_deref()))?
    {
        pipe
    } else {
        eprintln!("a wts-sh server does not appear to be running");
        return Ok(1);
    };

    let mut command_json = serde_json::to_string(&command).unwrap();
    command_json.push('\n');
    pipe.send(command_json.as_bytes())?;

    enable_virtual_console()?;

    let output_thread = std::thread::spawn({
        let mut pipe = pipe.copy()?;
        move || -> io::Result<DWORD> {
            let mut stdout = stdout();
            let mut buffer = [0u8; MAX_MESSAGE_SIZE];
            loop {
                let message_bytes_read = pipe.recv(&mut buffer)?;
                if message_bytes_read == 0 {
                    // server shutdown unexpectedly, just exit with error code
                    return Ok(123);
                }
                let event: OutputEvent =
                    bincode::deserialize(&buffer[..message_bytes_read]).unwrap();
                match event {
                    OutputEvent::Output { bytes } => {
                        stdout.write_all(&bytes)?;
                        stdout.flush()?;
                    }
                    OutputEvent::Exit { code } => return Ok(code),
                }
            }
        }
    });

    let input_interrupt = Arc::new(Interrupt::new()?);
    let input_thread = std::thread::spawn({
        let mut pipe = pipe.copy()?;
        let write_interrupt = input_interrupt.clone();
        move || -> io::Result<()> {
            let mut buffer: [MaybeUninit<INPUT_RECORD>; 1024] = MaybeUninit::uninit_array();
            let mut output_code_units: Vec<u16> = Vec::new();
            let mut output_bytes = Vec::new();
            let mut message_buffer = Vec::with_capacity(MAX_MESSAGE_SIZE);
            loop {
                match wait_for_input_events_or_interrupt(&write_interrupt)? {
                    Some(0) => continue,
                    None => return Ok(()),
                    Some(_) => {}
                }

                {
                    let span = trace_span!("read_events");
                    let _guard = span.enter();
                    for event in read_events(&mut buffer)? {
                        match event {
                            InputRecord::Key(key) => {
                                let uchar = unsafe { *key.uChar.UnicodeChar() };
                                trace!(
                                    uchar,
                                    key_down = key.bKeyDown != 0,
                                    key_code = key.wVirtualKeyCode,
                                    "key event"
                                );
                                if key.bKeyDown != 0 {
                                    output_code_units.push(uchar);
                                }
                            }
                            InputRecord::Mouse(_) => todo!(),
                            InputRecord::WindowBufferSize(_) => {
                                // The size provided here is a buffer size, not a screen size
                                let (width, height) = get_console_size()?;

                                debug!(width, height, "window resize event");
                                send_bincode(
                                    &mut pipe,
                                    &mut message_buffer,
                                    &InputEvent::Resize { width, height },
                                )?;
                            }
                            InputRecord::Menu(_) => todo!(),
                            InputRecord::Focus(_) => todo!(),
                        }
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
                    send_bincode(
                        &mut pipe,
                        &mut message_buffer,
                        &InputEvent::KeySequence {
                            bytes: Cow::Borrowed(&output_bytes),
                        },
                    )?;
                }
            }
        }
    });

    // Read thread will exit once connection is closed
    let code = output_thread.join().unwrap()?;

    // Interrupt write thread and wait for it to terminate
    input_interrupt.interrupt()?;
    input_thread.join().unwrap()?;

    Ok(code as i32)
}

fn server(options: &Options) -> io::Result<i32> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .init();

    info!("starting up wts-sh server");

    let session_id = get_current_session()?;

    if session_id == 0 {
        eprintln!("Attempted to launch server in session 0. This tool is designed to allow processes in session 0 to run processes in other sessions, not the reverse.");
        return Ok(1);
    }

    loop {
        let server_pipe = ServerPipe::new(&pipe_name(session_id, options.socket_name.as_deref()))?;

        let pipe = server_pipe.accept()?;

        std::thread::spawn(move || {
            if let Err(err) = server_thread(pipe) {
                eprintln!("error servicing client: {}", err);
            }
        });
    }
}

const MAX_MESSAGE_SIZE: usize = 64 * 1024;

fn server_thread(mut pipe: Pipe) -> io::Result<()> {
    let span = info_span!("run_command", command_line = tracing::field::Empty);
    let _guard = span.enter();

    let command: CommandSpec = {
        let mut command_json_buffer = vec![0u8; MAX_MESSAGE_SIZE];
        let bytes_read = pipe.recv(&mut command_json_buffer)?;
        command_json_buffer.truncate(bytes_read);
        serde_json::from_slice(&command_json_buffer).expect("failed to deserialize command")
    };

    debug!(?command, "parsed command");
    span.record("command_line", &&*command.command_line);

    let (mut pty_input_tx, pty_input_rx) = AnonPipe::pair()?;
    let (pty_output_tx, mut pty_output_rx) = AnonPipe::pair()?;

    let pty = Arc::new(Pty::new(
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
        pty_input_rx.handle(),
        pty_output_tx.handle(),
        0,
    )?);

    let exit_interrupt = Arc::new(Interrupt::new()?);

    let input_thread = std::thread::spawn({
        let mut pipe = pipe.copy()?;
        let pty = pty.clone();
        let exit_interrupt = exit_interrupt.clone();
        move || -> io::Result<()> {
            let span = debug_span!("server_thread::input_thread");
            let _guard = span.enter();

            let mut buffer = [0u8; MAX_MESSAGE_SIZE];

            loop {
                let event_bytes = match pipe.recv_or_interrupt(&mut buffer, &exit_interrupt)? {
                    Some(0) => return Ok(()),
                    Some(bytes_read) => &buffer[..bytes_read],
                    None => return Ok(()),
                };

                let event: InputEvent = bincode::deserialize(event_bytes).unwrap();

                trace!(?event, "input event");

                match event {
                    InputEvent::KeySequence { bytes } => {
                        pty_input_tx.write_all(&bytes)?;
                        pty_input_tx.flush()?;
                    }
                    InputEvent::Resize { width, height } => {
                        pty.resize(width, height)?;
                    }
                }
            }
        }
    });

    let output_thread = std::thread::spawn({
        let mut pipe = pipe.copy()?;
        move || -> io::Result<()> {
            let span = debug_span!("server_thread::output_thread");
            let _guard = span.enter();

            let mut read_buffer = [0u8; 4096];
            let mut message_buffer = Vec::with_capacity(MAX_MESSAGE_SIZE);
            loop {
                let read_count = pty_output_rx.read(&mut read_buffer)?;
                if read_count == 0 {
                    return Ok(());
                }

                send_bincode(
                    &mut pipe,
                    &mut message_buffer,
                    &OutputEvent::Output {
                        bytes: Cow::Borrowed(&read_buffer[..read_count]),
                    },
                )?;
            }
        }
    });

    let mut attribute_list = ProcThreadAttributeList::new(1)?;
    attribute_list.set_pseudoconsole(pty.pcon())?;
    let mut process = Process::spawn(
        &command.command_line,
        &attribute_list,
        &command.working_directory,
        command.environment.iter().map(|(k, v)| (&**k, &**v)),
    )?;

    let exit_code = process.wait()?;

    exit_interrupt.interrupt()?;
    // Drop console and pipe in output thread get EOF
    std::mem::drop(pty);
    std::mem::drop(pty_input_rx);
    std::mem::drop(pty_output_tx);

    input_thread.join().unwrap()?;
    output_thread.join().unwrap()?;

    let exit_message = bincode::serialize(&OutputEvent::Exit { code: exit_code }).unwrap();
    pipe.send(&exit_message)?;

    info!("finished servicing client");

    Ok(())
}

fn pipe_name(session_id: DWORD, socket_name: Option<&str>) -> String {
    // Ensure we use pipe in the global namespace, as we want access from different sessions to be possible
    if let Some(socket_name) = socket_name {
        format!(
            r#"\??\GLOBAL\pipe\Global\WtsSh.{}.{}"#,
            session_id, socket_name
        )
    } else {
        format!(r#"\??\GLOBAL\pipe\Global\WtsSh.{}"#, session_id)
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

fn send_bincode<T>(pipe: &mut Pipe, buffer: &mut Vec<u8>, message: &T) -> io::Result<()>
where
    T: Serialize,
{
    buffer.clear();
    {
        let mut message_writer = io::Cursor::new(&mut *buffer);
        bincode::serialize_into(&mut message_writer, message).unwrap();
    }
    pipe.send(buffer)?;
    Ok(())
}
