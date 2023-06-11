//! A crate to interact with the gpg-agent.
//!
//! https://www.gnupg.org/documentation/manuals/gnupg/Agent-Protocol.html#Agent-Protocol

use std::path::{Path, PathBuf};
use std::io::{Read, Write};
use std::fmt;
use std::env;

extern crate unix_socket;
use unix_socket::UnixStream;

extern crate assuan;
use assuan::{AssuanClient, AssuanError};

extern crate rustc_serialize;
use rustc_serialize::hex::FromHex;

mod helpers;
use helpers::{getuid, get_ttyname};

pub enum GpgAgentError {
    SocketNotFound,
    Protocol(AssuanError),
    InvalidPassword,
}

impl fmt::Display for GpgAgentError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GpgAgentError::SocketNotFound => write!(fmt, "Unable to find the gpg-agent socket"),
            GpgAgentError::Protocol(ref err) => err.fmt(fmt),
            GpgAgentError::InvalidPassword => write!(fmt, "Agent returned an invalid password"),
        }
    }
}

impl fmt::Debug for GpgAgentError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            GpgAgentError::SocketNotFound => write!(fmt, "Unable to find the gpg-agent socket"),
            GpgAgentError::Protocol(ref err) => err.fmt(fmt),
            GpgAgentError::InvalidPassword => write!(fmt, "Agent returned an invalid password"),
        }
    }
}

impl From<AssuanError> for GpgAgentError {
    fn from(err: AssuanError) -> Self {
        GpgAgentError::Protocol(err)
    }
}

pub struct GpgAgent<R, W> where R: Read, W: Write {
    client: AssuanClient<R, W>,
}

impl GpgAgent<UnixStream, UnixStream> {
    /// Try to find the gpg-agent socket in standard paths 
    /// `/run/user/<uid>/gnupg/S.gpg-agent` and `~/.gnupg/S.gpg-agent`.
    pub fn from_standard_paths() -> Result<Self, GpgAgentError> {
        // from /run/user/$UID
        let uid = format!("{}", getuid());
        let mut path = PathBuf::from("/run/user");
        path.push(uid);
        path.push("gnupg");
        path.push("S.gpg-agent");
        if let Ok(agent) = Self::from_path(path) {
            return Ok(agent);
        }

        // home folder
        if let Some(mut path) = env::home_dir() {
            path.push(".gnupg");
            path.push("S.gpg-agent");
            if let Ok(agent) = Self::from_path(path) {
                return Ok(agent);
            }
        }

        Err(GpgAgentError::SocketNotFound)
    }

    pub fn from_path<P: AsRef<Path>>(p: P) -> Result<Self, AssuanError> {
        let stream = UnixStream::connect(p)?;
        Ok(GpgAgent {
            client: AssuanClient::new(stream.try_clone().unwrap(), stream)?
        })
    }
}

impl<R, W> GpgAgent<R, W> where R: Read, W: Write{
    pub fn option(&mut self, name: &str, val: &str) -> Result<(), GpgAgentError> {
        self.client.option(name, val)
            .map_err(GpgAgentError::from)
    }

    pub fn update_startup_tty(&mut self) -> Result<(), GpgAgentError> {
        self.client.exec("UPDATESTARTUPTTY", &[])
            .map_err(GpgAgentError::from)
            .map(|_| ())
    }

    pub fn get_passphrase(&mut self, cache_id: &str, error_message: &str, prompt: &str, description: &str) -> Result<Vec<u8>, GpgAgentError> {
        let pass = self.client.exec("GET_PASSPHRASE",
                                         &[cache_id.as_bytes(), error_message.as_bytes(), prompt.as_bytes(), description.as_bytes()])
            .map(|res| res.0)?;
        pass.from_hex().or(Err(GpgAgentError::InvalidPassword))
    }

    pub fn clear_passphrase(&mut self, cache_id: &str) -> Result<(), GpgAgentError> {
        self.client.exec("CLEAR_PASSPHRASE", &[cache_id.as_bytes()])
            .map_err(GpgAgentError::from)
            .map(|_| ())
    }

    /// Try to set the ttyname to the current tty, using the POSIX ttyname()
    /// function.
    ///
    /// This is just a convinience method, you can do this with a custom ttyname,
    /// using the `option()` method.
    ///
    /// ```no_run
    ///     extern crate gpgagent;
    ///     let mut agent = gpgagent::GpgAgent::from_standard_paths().unwrap();
    ///     agent.option("ttyname", "/dev/pts/4").unwrap();
    /// ```
    #[cfg(unix)]
    pub fn setopt_ttyname(&mut self) -> Result<(), GpgAgentError> {
        if let Some(name) = get_ttyname() {
            self.option("ttyname", &name)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Stdio, Command};

    #[test]
    fn gpg_agent() {
        let mut cmd = Command::new("gpg-agent")
            .arg("--server")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(AssuanClient::from_child(&mut cmd).is_ok())
    }

    #[test]
    fn gpg_agent_socket() {
        let stream = UnixStream::connect("/run/user/1000/gnupg/S.gpg-agent").unwrap();
        assert!(AssuanClient::new(stream.try_clone().unwrap(), stream).is_ok())
    }
}

