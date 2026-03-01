#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{env, ffi::CString, io, mem::offset_of, ptr, result};

use libc::{
    BPF_ABS, BPF_JEQ, BPF_JMP, BPF_JUMP, BPF_K, BPF_LD, BPF_RET, BPF_STMT, BPF_W, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_SET_MODE_FILTER
};

mod bindings;
mod errors;

use errors::{ProgramError, Result};

fn main() -> Result<()> {
    let mut args = env::args();
    let prog_name = args
        .next()
        .expect("First argument should be this program's name");

    // This is cool! Result has a FromIterator implementation that lets me do this!
    let backing_args_vec = args
        .map(CString::new)
        .collect::<result::Result<Vec<_>, _>>()?;
    let args_vec = {
        let mut tmp = backing_args_vec
            .iter()
            .map(|arg_cstr| arg_cstr.as_ptr())
            .collect::<Vec<_>>();
        tmp.push(ptr::null());
        tmp
    };

    if backing_args_vec.is_empty() {
        // eprintln!("Usage: {prog_name} <command to run> [<args>]");
        // std::process::exit(1);
        return Err(ProgramError::NoCLISpecifiedProgram);
    }

    set_no_new_privs_attr()?;

    setup_seccomp_filters()?;

    unsafe { execvp(args_vec[0], args_vec.as_ptr()) }?;

    Ok(())
}

fn set_no_new_privs_attr() -> Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1usize, 0usize, 0usize, 0usize) } < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

unsafe fn execvp(
    program_name: *const libc::c_char,
    args: *const *const libc::c_char,
) -> Result<()> {
    if unsafe { libc::execvp(program_name, args) } < 0 {
        Err(io::Error::last_os_error().into())
    } else {
        unsafe {
            std::hint::unreachable_unchecked();
        }
    }
}

fn setup_seccomp_filters() -> Result<()> {
    let mut bpf_insts = unsafe {
        [
            // Load arch
            BPF_STMT(
                (BPF_LD | BPF_W | BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, arch) as u32,
            ),

            // If arch == AUDIT_ARCH_X86_64, continue; else kill
            BPF_JUMP(
                (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                bindings::AUDIT_ARCH_X86_64,
                1,
                0,
            ),
            BPF_STMT((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS),

            // Load syscall number
            BPF_STMT(
                (BPF_LD | BPF_W | BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, nr) as u32,
            ),

            // If nr == SYS_clone, trigger a SECCOMP_RET_TRAP
            BPF_JUMP(
                (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                libc::SYS_clone as u32,
                0,
                1,
            ),
            BPF_STMT((BPF_RET | BPF_K) as u16, libc::SECCOMP_RET_TRAP),

            // If nr == SYS_clone3, also trigger a SECCOMP_RET_TRAP
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as u16, libc::SYS_clone3 as u32, 0, 1),
            BPF_STMT((BPF_RET | BPF_K) as u16, libc::SECCOMP_RET_TRAP),

            // Otherwise, allow
            BPF_STMT((BPF_RET | BPF_K) as u16, SECCOMP_RET_ALLOW)
        ]
    };

    let bpf_prog = libc::sock_fprog {
        len: bpf_insts.len() as u16,
        filter: (&raw mut bpf_insts).cast()
    };

    if unsafe {
        libc::syscall(libc::SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &raw const bpf_prog)
    } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}
