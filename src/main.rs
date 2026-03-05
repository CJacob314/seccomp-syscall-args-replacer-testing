#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{
    io,
    mem::offset_of,
    sync::atomic::{AtomicI32, Ordering},
};

use libc::{
    BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_JUMP, BPF_K, BPF_LD, BPF_RET, BPF_STMT, BPF_W,
    SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_SET_MODE_FILTER,
};

mod bindings;
mod errors;

use errors::{ProgramError, Result};

fn main() -> Result<()> {
    /*
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
        return Err(ProgramError::NoCLISpecifiedProgram);
    }
    */

    set_no_new_privs_attr()?;

    setup_sigsys_handler()?;

    setup_seccomp_filters()?;

    test()?;

    /* unsafe { execvp(args_vec[0], args_vec.as_ptr()) }?; */

    Ok(())
}

fn test() -> Result<()> {
    const STACKSZ: usize = 16 * 1024; // 16 KiB stack

    const CLONE_FLAGS: libc::c_int = libc::CLONE_VM | libc::CLONE_THREAD | libc::CLONE_SIGHAND;

    let child_pid_atomic = AtomicI32::new(0); // 0 is an invalid TGID

    // Allocate stack for child task
    let stack_base = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            STACKSZ,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    } as *mut u8;

    if stack_base == libc::MAP_FAILED.cast() {
        return Err(io::Error::last_os_error().into());
    }

    let stack_top = unsafe { stack_base.add(STACKSZ) };

    // Child task function
    extern "C" fn child_func(arg: *mut libc::c_void) -> libc::c_int {
        unsafe {
            libc::write(
                libc::STDOUT_FILENO,
                c"Hello from the child task!".as_ptr().cast(),
                26,
            );
        };

        let child_pid = unsafe { &*(arg as *const AtomicI32) };
        child_pid.store(unsafe { libc::getpid() }, Ordering::Relaxed);

        0
    }

    if unsafe {
        libc::clone(
            child_func,
            stack_top.cast(),
            CLONE_FLAGS,
            &raw const child_pid_atomic as *mut libc::c_void,
        )
    } < 0
    {
        return Err(io::Error::last_os_error().into());
    }

    let parent_pid = unsafe { libc::getpid() };

    let mut child_pid = 0;
    loop {
        std::hint::spin_loop();

        child_pid = child_pid_atomic.load(Ordering::Relaxed);

        if child_pid != 0 {
            break;
        }
    }

    if child_pid == parent_pid {
        // Then this solution didn't successfully and out the CLONE_THREAD, so fail
        Err(ProgramError::SeccompFlagAdjustmentFailed)
    } else {
        Ok(())
    }
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
    // BPF logic: TRAP only when syscall ABI is x86-64 && syscall is a sys_clone && (flags &
    // CLONE_THREAD). Allow everything else without trap
    let mut bpf_insts = unsafe {
        [
            // Load and test arch
            BPF_STMT(
                (BPF_LD | BPF_W | BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, arch) as u32,
            ),
            BPF_JUMP(
                (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                bindings::AUDIT_ARCH_X86_64,
                1,
                0,
            ),
            BPF_STMT((BPF_RET | BPF_K) as u16, SECCOMP_RET_KILL_PROCESS),
            // Load and test syscall number. Jump over everything to allow if not clone
            BPF_STMT(
                (BPF_LD | BPF_W | BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, nr) as u32,
            ),
            BPF_JUMP(
                (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                libc::SYS_clone as u32,
                0,
                4, // Next 4 handle if it's a clone call
            ),
            // cBPF register A = (u32)args[0] (low 32 bits of flags)
            BPF_STMT(
                (BPF_LD | BPF_W | BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, args) as u32,
            ),
            // A &= CLONE_THREAD
            BPF_STMT(
                (BPF_ALU | BPF_AND | BPF_K) as u16,
                libc::CLONE_THREAD as u32,
            ),
            // If (A == 0) ( meaning !(flags & CLONE_THREAD) ), jump to ALLOW to prevent infinite looping
            BPF_JUMP((BPF_JMP | BPF_JEQ | BPF_K) as u16, 0, 1, 0),
            // Otherwise, trap
            BPF_STMT((BPF_RET | BPF_K) as u16, libc::SECCOMP_RET_TRAP),
            // Allow inst
            BPF_STMT((BPF_RET | BPF_K) as u16, SECCOMP_RET_ALLOW),
        ]
    };

    let bpf_prog = libc::sock_fprog {
        len: bpf_insts.len() as u16,
        filter: (&raw mut bpf_insts).cast(),
    };

    if unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            0,
            &raw const bpf_prog,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

fn setup_sigsys_handler() -> Result<()> {
    let mut act: libc::sigaction = unsafe { std::mem::zeroed() };

    act.sa_flags = libc::SA_SIGINFO | libc::SA_NODEFER;
    act.sa_sigaction = sigsys_handler as *const () as usize;
    assert_ne!(unsafe { libc::sigemptyset(&mut act.sa_mask) }, -1);

    if unsafe { libc::sigaction(libc::SIGSYS, &act, std::ptr::null_mut()) } != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

// TODO: Remove this no_mangle once everything's working
#[unsafe(no_mangle)]
extern "C" fn sigsys_handler(
    _sig: libc::c_int,
    info: *mut bindings::siginfo_t,
    uctx: *mut libc::c_void,
) {
    if info.is_null() {
        panic!("*mut siginfo_t passed to sigsys_handler was null");
    }
    let info = unsafe { &*info };

    if info.si_code != bindings::SYS_SECCOMP as i32 {
        panic!("Received non-seccomp SIGSYS");
    }

    // TODO: Also handle the clone3 system call
    if unsafe { info._sifields._sigsys._syscall } != libc::SYS_clone as i32 {
        return;
    }

    let ctx = &mut unsafe { *(uctx as *mut libc::ucontext_t) };

    // clone_flags is in %rdi on x86-64
    let rdi = ctx.uc_mcontext.gregs[libc::REG_RDI as usize] as u64;

    // And **out** CLONE_THREAD from flags
    ctx.uc_mcontext.gregs[libc::REG_RDI as usize] &= !libc::CLONE_THREAD as i64;

    // Re-execute the system call
    // ctx.uc_mcontext.gregs[libc::REG_RIP as usize] -= 2 as libc::greg_t;
    // ctx.uc_mcontext.gregs[libc::REG_RIP as usize] = unsafe { info._sifields._sigsys._call_addr } as i64 - 2;

    // DEBUG NOTE: The program should receive a SIGSEGV if we can change the %rip register AT
    // ALL with this style of assignment
    ctx.uc_mcontext.gregs[libc::REG_RIP as usize] = 0;
}
