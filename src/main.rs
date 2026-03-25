#![cfg(all(target_os = "linux", target_arch = "x86_64"))]

use std::{
    io, mem::{self, offset_of}, os::fd::{AsRawFd, FromRawFd, OwnedFd}, panic, sync::{Arc, atomic::{AtomicI32, Ordering}}, thread::{self, JoinHandle}
};

use libc::{
    BPF_ABS, BPF_ALU, BPF_AND, BPF_JEQ, BPF_JMP, BPF_JUMP, BPF_K, BPF_LD, BPF_RET, BPF_STMT, BPF_W, SECCOMP_FILTER_FLAG_NEW_LISTENER, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SECCOMP_SET_MODE_FILTER
};

mod bindings;
mod errors;

use errors::{ProgramError, Result};

static mut UNOTIFY_LISTENER_FD: Option<OwnedFd> = None;

fn main() -> Result<()> {
    set_no_new_privs_attr()?;

    setup_sigsys_handler()?;

    let supervisor_join_handle = spawn_supervisor_thread();

    setup_seccomp_filters()?;

    test_clone()?;

    test_clone3()?;

    if let Err(e) = supervisor_join_handle.join() {
        // Thread panicked! This is bad, just resume the panic stack-unwind.
        panic::resume_unwind(e);
    }

    Ok(())
}

fn test_clone3() -> Result<()> {
    // On my system, std::thread::spawn ends up making a `clone3` syscall
    let child_pid_atomic = Arc::new(AtomicI32::new(0));
    let child_pid_atomic_clone = child_pid_atomic.clone();

    let handle = thread::spawn(move || {
        child_pid_atomic_clone.store(unsafe { libc::getpid() }, Ordering::Relaxed);
    });

    let child_pid = loop {
        std::hint::spin_loop();

        let pid = child_pid_atomic.load(Ordering::Relaxed);

        if pid != 0 {
            break pid;
        }
    };

    handle.join(); // The thread will not panic.
    
    let parent_pid = unsafe { libc::getpid() };
    if child_pid == parent_pid {
        // Then this solution didn't successfully and out the CLONE_THREAD, so fail
        Err(ProgramError::SeccompFlagAdjustmentFailed)
    } else {
        println!("Despite passing CLONE_THREAD in clone3, the child_pid, {child_pid} isn't equal to the parent_pid, {parent_pid}");
        Ok(())
    }
}

fn test_clone() -> Result<()> {
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
                c"Hello from the child task!\n".as_ptr().cast(),
                27,
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

    let child_pid = loop {
        std::hint::spin_loop();

        let pid = child_pid_atomic.load(Ordering::Relaxed);

        if pid != 0 {
            break pid;
        }
    };

    if child_pid == parent_pid {
        // Then this solution didn't successfully and out the CLONE_THREAD, so fail
        Err(ProgramError::SeccompFlagAdjustmentFailed)
    } else {
        Ok(())
    }
}

fn spawn_supervisor_thread() -> JoinHandle<()> {
    #[allow(static_mut_refs)]
    thread::spawn(|| {
        let listener_fd = unsafe {
            UNOTIFY_LISTENER_FD.as_ref().unwrap().as_raw_fd()
        };

        let mut req: libc::seccomp_notif = unsafe { mem::zeroed() };

        if unsafe { libc::ioctl(listener_fd, bindings::SECCOMP_IOCTL_NOTIF_RECV, &raw mut req) } < 0 {
            panic!("SECCOMP_IOCTL_NOTIF_RECV ioctl call failed: {}", io::Error::last_os_error());
        }

        if req.data.nr as i64 != libc::SYS_clone3 {
            panic!("unexpected seccomp_unotify syscall number: expected SYS_clone3={}, got {}", libc::SYS_clone3, req.data.nr);
        }

        if (req.data.args[1] as usize) < 8 {
            panic!("clone3 clone_args struct too small: {}", req.data.args[1]);
        }

        let flags_ptr = req.data.args[0] as *mut u64;

        if flags_ptr.is_null() {
            panic!("clone3 clone_args struct pointer was null");
        }

        unsafe {
            *flags_ptr &= !(libc::CLONE_THREAD as u64);
        }

        let mut resp = libc::seccomp_notif_resp {
            id: req.id,
            val: 0,
            error: 0,
            flags: libc::SECCOMP_USER_NOTIF_FLAG_CONTINUE as u32,
        };

        if unsafe { libc::ioctl(listener_fd, bindings::SECCOMP_IOCTL_NOTIF_SEND, &raw mut resp) } < 0 {
            panic!("SECCOMP_IOCTL_NOTIF_SEND ioctl call failed: {}", io::Error::last_os_error());
        }
    })
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

            // Load syscall number
            BPF_STMT(
                (BPF_LD | BPF_W | BPF_ABS) as u16,
                offset_of!(libc::seccomp_data, nr) as u32,
            ),

            // If it's SYS_clone3, immediately trigger unotify behavior
            BPF_JUMP(
                (BPF_JMP | BPF_JEQ | BPF_K) as u16,
                libc::SYS_clone3 as u32,
                0,
                1,
            ),
            BPF_STMT(
                (BPF_RET | BPF_K) as u16,
                libc::SECCOMP_RET_USER_NOTIF,
            ),

            // If it's not SYS_clone and it's not SYS_clone3, just jump to allow
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

    let seccomp_ret = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &raw const bpf_prog,
        )
    };

    if seccomp_ret < 0
    {
        Err(io::Error::last_os_error().into())
    } else {
        unsafe {
            UNOTIFY_LISTENER_FD = Some(OwnedFd::from_raw_fd(seccomp_ret as i32));
        }
        Ok(())
    }
}

fn setup_sigsys_handler() -> Result<()> {
    let mut act: libc::sigaction = unsafe { mem::zeroed() };

    act.sa_flags = libc::SA_SIGINFO;
    act.sa_sigaction = sigsys_handler as *const () as usize;
    assert_ne!(unsafe { libc::sigemptyset(&mut act.sa_mask) }, -1);

    if unsafe { libc::sigaction(libc::SIGSYS, &act, std::ptr::null_mut()) } != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

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

    if unsafe { info._sifields._sigsys._syscall } != libc::SYS_clone as i32 {
        return;
    }

    let ctx = unsafe { &mut *(uctx as *mut libc::ucontext_t) };

    // clone_flags is in %rdi on x86-64
    let [rdi, rip] = unsafe {
        ctx.uc_mcontext
            .gregs
            .get_disjoint_unchecked_mut([libc::REG_RDI, libc::REG_RIP].map(|x| x as usize))
    };

    // And **out** CLONE_THREAD from flags
    *rdi &= !(libc::CLONE_THREAD as i64);

    // Re-execute the system call
    *rip -= 2;
}
