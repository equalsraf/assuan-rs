
use std::process::{Child, ChildStdin, ChildStdout};
use std::io::Error as IoError;
use std::io::{Write, BufReader, BufRead, Read};
use std::fmt;

extern crate url;
use url::percent_encoding::{percent_encode, EncodeSet};

#[macro_use]
extern crate log;

// (msg, data)
type CallResult = (String, String);

#[allow(non_camel_case_types)]
#[derive(Clone)]
struct ARG_ENCODE_SET;

impl EncodeSet for ARG_ENCODE_SET {
    fn contains(&self, byte: u8) -> bool {
        [b'\r', b'\n', b'%', b' '].contains(&byte)
    }
}

pub enum AssuanError {
    IoError(IoError),
    Other(String),
}

impl fmt::Display for AssuanError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AssuanError::IoError(ref err) => err.fmt(fmt),
            AssuanError::Other(ref desc) => write!(fmt, "{}", desc),
        }
    }
}

impl fmt::Debug for AssuanError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            AssuanError::IoError(ref err) => err.fmt(fmt),
            AssuanError::Other(ref desc) => write!(fmt, "{}", desc),
        }
    }
}

impl From<IoError> for AssuanError {
    fn from(err: IoError) -> Self {
        AssuanError::IoError(err)
    }
}

/// Assuan client, check the Assuan protocol for details
///
/// https://www.gnupg.org/documentation/manuals/assuan/index.html
pub struct AssuanClient<R, W> where R: Read, W: Write {
    w: W,
    r: BufReader<R>,
}

impl AssuanClient<ChildStdout, ChildStdin>  {
    /// Take hold of a child's stdin and stdout and use them as communication channel for the
    /// Assuan protocol
    ///  
    /// The child stdin/out must be piped for this to work e.g.
    ///
    ///     # use assuan::*;
    ///     # use std::process::{Command, Child, Stdio, ChildStdin, ChildStdout};
    ///     let mut cmd = Command::new("pinentry")
    ///                 .stdin(Stdio::piped())
    ///                 .stdout(Stdio::piped())
    ///                 .stderr(Stdio::null())
    ///                 .spawn()
    ///                 .unwrap();
    ///     assert!(AssuanClient::from_child(&mut cmd).is_ok())
    ///
    /// It is up to the caller to make sure the child is not killed.
    pub fn from_child(c: &mut Child) -> Result<AssuanClient<ChildStdout, ChildStdin>, AssuanError> {
        match (c.stdin.take(), c.stdout.take()) {
            (Some(w), Some(r)) => Ok(AssuanClient {
                w: w,
                r: BufReader::new(r),
            }),
            _ => Err(AssuanError::Other("Failed to setup stdin/out".to_owned())),
        }
    }
}

impl<R, W> AssuanClient<R, W> where R: Read, W: Write {
    /// Creates a new client. Before returning make sure to receive the first
    /// OK message from the server.
    pub fn new(r: R, w: W) -> Result<AssuanClient<R, W>, AssuanError> {
        let mut p = AssuanClient {
            w: w,
            r: BufReader::new(r),
        };

        // Wait for server response
        p.wait_response()?;
        Ok(p)
    }

    /// Execute command with given arguments
    pub fn exec(&mut self, name: &str, args: &[&[u8]]) -> Result<CallResult, AssuanError> {
        // FIXME: check command name for invalid chars, spaces
        let mut cmd = format!("{}", name);
        // encode arguments
        for arg in args {
            cmd.push(' ');
            for chunk in percent_encode(arg, ARG_ENCODE_SET) {
                cmd.push_str(chunk);
            }
        }
        self.call(&cmd)
    }

    fn call(&mut self, command: &str) -> Result<CallResult, AssuanError> {
        debug!("> {}", command);
        match self.w.write_all(command.as_bytes()) {
            Err(err) => return Err(AssuanError::IoError(err)),
            Ok(_) => (),
        }
        match self.w.write_all("\n".as_bytes()) {
            Err(err) => return Err(AssuanError::IoError(err)),
            Ok(_) => (),
        }
        match self.w.flush() {
            Err(err) => return Err(AssuanError::IoError(err)),
            Ok(_) => (),
        }

        self.wait_response()
    }

    pub fn option(&mut self, name: &str, val: &str) -> Result<(), AssuanError> {
        self.exec("OPTION", &[name.as_bytes(), val.as_bytes()]).map(|_| ())
    }

    fn wait_response(&mut self) -> Result<CallResult, AssuanError> {
        let msg;
        let mut data = String::new();

        loop {
            // Read lines until we get an ERR or an OK
            let mut line = String::new();
            match self.r.read_line(&mut line) {
                Err(err) => return Err(AssuanError::IoError(err)),
                Ok(_) => (),
            }

            debug!("< {}", line);
            // With the exception of the trailing NL, the output
            // should have no NL bytes (they are escaped as %0A)
            let resp = line.trim_end_matches("\n");

            if resp.starts_with("OK") {
                msg = resp[2..].to_owned();
                break;
            } else if resp.starts_with("ERR ") {
                msg = resp[3..].to_owned();
                return Err(AssuanError::Other(msg));
            } else if resp.starts_with("D ") {
                data.push_str(&resp[2..]);
            } else if resp.starts_with("S ") {
            } else if resp.starts_with("INQUIRE") {
                return Err(AssuanError::Other("Received unsupported INQUIRE message"
                                                    .to_owned()));
            } else if resp.starts_with("#") {
                // Comments - ignore
            } else {
                // Error
                return Err(AssuanError::Other("Unsupported Assuan response".to_owned()));
            }
        }

        // FIXME: unescape data
        Ok((msg, data))
    }
}

impl<R, W> Drop for AssuanClient<R, W> where R: Read, W: Write {
    fn drop(&mut self) {
        let _ = self.call("BYE");
    }
}
