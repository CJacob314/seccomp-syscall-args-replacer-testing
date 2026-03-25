#define _GNU_SOURCE
#include <asm/ioctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>

// Pictured below: the disgustingly hacky solution for the GitHub issue that's been open since 2016: https://github.com/jethrogb/rust-cexpr/issues/3
const __u64 _SECCOMP_IOCTL_NOTIF_RECV = SECCOMP_IOCTL_NOTIF_RECV;
#undef SECCOMP_IOCTL_NOTIF_RECV
const __u64 SECCOMP_IOCTL_NOTIF_RECV = _SECCOMP_IOCTL_NOTIF_RECV;

const __u64 _SECCOMP_IOCTL_NOTIF_SEND = SECCOMP_IOCTL_NOTIF_SEND;
#undef SECCOMP_IOCTL_NOTIF_SEND
const __u64 SECCOMP_IOCTL_NOTIF_SEND = _SECCOMP_IOCTL_NOTIF_SEND;

