/* This `Backtrace as BT` to confuse the thiserror macro might be crimes against humanity.
 * I'm so, so sorry.
 */
use std::{backtrace::Backtrace as BT, ffi::NulError, io};

use thiserror::Error;

#[derive(Error)]
pub enum ProgramError {
    #[error("libc syscall wrapper error\nsource: {src}\nbacktrace:\n{bt}")]
    SyscallWrapperError {
        src: io::Error,
        bt: BT,
    },

    #[error("no CLI-specified program to run")]
    NoCLISpecifiedProgram,

    #[error("NulError in CString creation")]
    CStringCreation(#[from] NulError)
}

// Forward the Debug impl to the Display impl for prettier backtrace printing
impl std::fmt::Debug for ProgramError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl From<io::Error> for ProgramError {
    fn from(src: io::Error) -> Self {
        Self::SyscallWrapperError {
            src,
            bt: BT::capture(),
        }
    }
}

pub type Result<T> = std::result::Result<T, ProgramError>;
