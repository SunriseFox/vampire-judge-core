#include <map>
#include <string>

using std::map;
using std::string;

void initialize(map<int, string> &syscallName)
{

#ifdef __NR_read
  syscallName[__NR_read] = "read";
#endif

#ifdef __NR_write
  syscallName[__NR_write] = "write";
#endif

#ifdef __NR_open
  syscallName[__NR_open] = "open";
#endif

#ifdef __NR_close
  syscallName[__NR_close] = "close";
#endif

#ifdef __NR_stat
  syscallName[__NR_stat] = "stat";
#endif

#ifdef __NR_fstat
  syscallName[__NR_fstat] = "fstat";
#endif

#ifdef __NR_lstat
  syscallName[__NR_lstat] = "lstat";
#endif

#ifdef __NR_poll
  syscallName[__NR_poll] = "poll";
#endif

#ifdef __NR_lseek
  syscallName[__NR_lseek] = "lseek";
#endif

#ifdef __NR_mmap
  syscallName[__NR_mmap] = "mmap";
#endif

#ifdef __NR_mprotect
  syscallName[__NR_mprotect] = "mprotect";
#endif

#ifdef __NR_munmap
  syscallName[__NR_munmap] = "munmap";
#endif

#ifdef __NR_brk
  syscallName[__NR_brk] = "brk";
#endif

#ifdef __NR_rt_sigaction
  syscallName[__NR_rt_sigaction] = "rt_sigaction";
#endif

#ifdef __NR_rt_sigprocmask
  syscallName[__NR_rt_sigprocmask] = "rt_sigprocmask";
#endif

#ifdef __NR_rt_sigreturn
  syscallName[__NR_rt_sigreturn] = "rt_sigreturn";
#endif

#ifdef __NR_ioctl
  syscallName[__NR_ioctl] = "ioctl";
#endif

#ifdef __NR_pread64
  syscallName[__NR_pread64] = "pread64";
#endif

#ifdef __NR_pwrite64
  syscallName[__NR_pwrite64] = "pwrite64";
#endif

#ifdef __NR_readv
  syscallName[__NR_readv] = "readv";
#endif

#ifdef __NR_writev
  syscallName[__NR_writev] = "writev";
#endif

#ifdef __NR_access
  syscallName[__NR_access] = "access";
#endif

#ifdef __NR_pipe
  syscallName[__NR_pipe] = "pipe";
#endif

#ifdef __NR_select
  syscallName[__NR_select] = "select";
#endif

#ifdef __NR_sched_yield
  syscallName[__NR_sched_yield] = "sched_yield";
#endif

#ifdef __NR_mremap
  syscallName[__NR_mremap] = "mremap";
#endif

#ifdef __NR_msync
  syscallName[__NR_msync] = "msync";
#endif

#ifdef __NR_mincore
  syscallName[__NR_mincore] = "mincore";
#endif

#ifdef __NR_madvise
  syscallName[__NR_madvise] = "madvise";
#endif

#ifdef __NR_shmget
  syscallName[__NR_shmget] = "shmget";
#endif

#ifdef __NR_shmat
  syscallName[__NR_shmat] = "shmat";
#endif

#ifdef __NR_shmctl
  syscallName[__NR_shmctl] = "shmctl";
#endif

#ifdef __NR_dup
  syscallName[__NR_dup] = "dup";
#endif

#ifdef __NR_dup2
  syscallName[__NR_dup2] = "dup2";
#endif

#ifdef __NR_pause
  syscallName[__NR_pause] = "pause";
#endif

#ifdef __NR_nanosleep
  syscallName[__NR_nanosleep] = "nanosleep";
#endif

#ifdef __NR_getitimer
  syscallName[__NR_getitimer] = "getitimer";
#endif

#ifdef __NR_alarm
  syscallName[__NR_alarm] = "alarm";
#endif

#ifdef __NR_setitimer
  syscallName[__NR_setitimer] = "setitimer";
#endif

#ifdef __NR_getpid
  syscallName[__NR_getpid] = "getpid";
#endif

#ifdef __NR_sendfile
  syscallName[__NR_sendfile] = "sendfile";
#endif

#ifdef __NR_socket
  syscallName[__NR_socket] = "socket";
#endif

#ifdef __NR_connect
  syscallName[__NR_connect] = "connect";
#endif

#ifdef __NR_accept
  syscallName[__NR_accept] = "accept";
#endif

#ifdef __NR_sendto
  syscallName[__NR_sendto] = "sendto";
#endif

#ifdef __NR_recvfrom
  syscallName[__NR_recvfrom] = "recvfrom";
#endif

#ifdef __NR_sendmsg
  syscallName[__NR_sendmsg] = "sendmsg";
#endif

#ifdef __NR_recvmsg
  syscallName[__NR_recvmsg] = "recvmsg";
#endif

#ifdef __NR_shutdown
  syscallName[__NR_shutdown] = "shutdown";
#endif

#ifdef __NR_bind
  syscallName[__NR_bind] = "bind";
#endif

#ifdef __NR_listen
  syscallName[__NR_listen] = "listen";
#endif

#ifdef __NR_getsockname
  syscallName[__NR_getsockname] = "getsockname";
#endif

#ifdef __NR_getpeername
  syscallName[__NR_getpeername] = "getpeername";
#endif

#ifdef __NR_socketpair
  syscallName[__NR_socketpair] = "socketpair";
#endif

#ifdef __NR_setsockopt
  syscallName[__NR_setsockopt] = "setsockopt";
#endif

#ifdef __NR_getsockopt
  syscallName[__NR_getsockopt] = "getsockopt";
#endif

#ifdef __NR_clone
  syscallName[__NR_clone] = "clone";
#endif

#ifdef __NR_fork
  syscallName[__NR_fork] = "fork";
#endif

#ifdef __NR_vfork
  syscallName[__NR_vfork] = "vfork";
#endif

#ifdef __NR_execve
  syscallName[__NR_execve] = "execve";
#endif

#ifdef __NR_exit
  syscallName[__NR_exit] = "exit";
#endif

#ifdef __NR_wait4
  syscallName[__NR_wait4] = "wait4";
#endif

#ifdef __NR_kill
  syscallName[__NR_kill] = "kill";
#endif

#ifdef __NR_uname
  syscallName[__NR_uname] = "uname";
#endif

#ifdef __NR_semget
  syscallName[__NR_semget] = "semget";
#endif

#ifdef __NR_semop
  syscallName[__NR_semop] = "semop";
#endif

#ifdef __NR_semctl
  syscallName[__NR_semctl] = "semctl";
#endif

#ifdef __NR_shmdt
  syscallName[__NR_shmdt] = "shmdt";
#endif

#ifdef __NR_msgget
  syscallName[__NR_msgget] = "msgget";
#endif

#ifdef __NR_msgsnd
  syscallName[__NR_msgsnd] = "msgsnd";
#endif

#ifdef __NR_msgrcv
  syscallName[__NR_msgrcv] = "msgrcv";
#endif

#ifdef __NR_msgctl
  syscallName[__NR_msgctl] = "msgctl";
#endif

#ifdef __NR_fcntl
  syscallName[__NR_fcntl] = "fcntl";
#endif

#ifdef __NR_flock
  syscallName[__NR_flock] = "flock";
#endif

#ifdef __NR_fsync
  syscallName[__NR_fsync] = "fsync";
#endif

#ifdef __NR_fdatasync
  syscallName[__NR_fdatasync] = "fdatasync";
#endif

#ifdef __NR_truncate
  syscallName[__NR_truncate] = "truncate";
#endif

#ifdef __NR_ftruncate
  syscallName[__NR_ftruncate] = "ftruncate";
#endif

#ifdef __NR_getdents
  syscallName[__NR_getdents] = "getdents";
#endif

#ifdef __NR_getcwd
  syscallName[__NR_getcwd] = "getcwd";
#endif

#ifdef __NR_chdir
  syscallName[__NR_chdir] = "chdir";
#endif

#ifdef __NR_fchdir
  syscallName[__NR_fchdir] = "fchdir";
#endif

#ifdef __NR_rename
  syscallName[__NR_rename] = "rename";
#endif

#ifdef __NR_mkdir
  syscallName[__NR_mkdir] = "mkdir";
#endif

#ifdef __NR_rmdir
  syscallName[__NR_rmdir] = "rmdir";
#endif

#ifdef __NR_creat
  syscallName[__NR_creat] = "creat";
#endif

#ifdef __NR_link
  syscallName[__NR_link] = "link";
#endif

#ifdef __NR_unlink
  syscallName[__NR_unlink] = "unlink";
#endif

#ifdef __NR_symlink
  syscallName[__NR_symlink] = "symlink";
#endif

#ifdef __NR_readlink
  syscallName[__NR_readlink] = "readlink";
#endif

#ifdef __NR_chmod
  syscallName[__NR_chmod] = "chmod";
#endif

#ifdef __NR_fchmod
  syscallName[__NR_fchmod] = "fchmod";
#endif

#ifdef __NR_chown
  syscallName[__NR_chown] = "chown";
#endif

#ifdef __NR_fchown
  syscallName[__NR_fchown] = "fchown";
#endif

#ifdef __NR_lchown
  syscallName[__NR_lchown] = "lchown";
#endif

#ifdef __NR_umask
  syscallName[__NR_umask] = "umask";
#endif

#ifdef __NR_gettimeofday
  syscallName[__NR_gettimeofday] = "gettimeofday";
#endif

#ifdef __NR_getrlimit
  syscallName[__NR_getrlimit] = "getrlimit";
#endif

#ifdef __NR_getrusage
  syscallName[__NR_getrusage] = "getrusage";
#endif

#ifdef __NR_sysinfo
  syscallName[__NR_sysinfo] = "sysinfo";
#endif

#ifdef __NR_times
  syscallName[__NR_times] = "times";
#endif

#ifdef __NR_ptrace
  syscallName[__NR_ptrace] = "ptrace";
#endif

#ifdef __NR_getuid
  syscallName[__NR_getuid] = "getuid";
#endif

#ifdef __NR_syslog
  syscallName[__NR_syslog] = "syslog";
#endif

#ifdef __NR_getgid
  syscallName[__NR_getgid] = "getgid";
#endif

#ifdef __NR_setuid
  syscallName[__NR_setuid] = "setuid";
#endif

#ifdef __NR_setgid
  syscallName[__NR_setgid] = "setgid";
#endif

#ifdef __NR_geteuid
  syscallName[__NR_geteuid] = "geteuid";
#endif

#ifdef __NR_getegid
  syscallName[__NR_getegid] = "getegid";
#endif

#ifdef __NR_setpgid
  syscallName[__NR_setpgid] = "setpgid";
#endif

#ifdef __NR_getppid
  syscallName[__NR_getppid] = "getppid";
#endif

#ifdef __NR_getpgrp
  syscallName[__NR_getpgrp] = "getpgrp";
#endif

#ifdef __NR_setsid
  syscallName[__NR_setsid] = "setsid";
#endif

#ifdef __NR_setreuid
  syscallName[__NR_setreuid] = "setreuid";
#endif

#ifdef __NR_setregid
  syscallName[__NR_setregid] = "setregid";
#endif

#ifdef __NR_getgroups
  syscallName[__NR_getgroups] = "getgroups";
#endif

#ifdef __NR_setgroups
  syscallName[__NR_setgroups] = "setgroups";
#endif

#ifdef __NR_setresuid
  syscallName[__NR_setresuid] = "setresuid";
#endif

#ifdef __NR_getresuid
  syscallName[__NR_getresuid] = "getresuid";
#endif

#ifdef __NR_setresgid
  syscallName[__NR_setresgid] = "setresgid";
#endif

#ifdef __NR_getresgid
  syscallName[__NR_getresgid] = "getresgid";
#endif

#ifdef __NR_getpgid
  syscallName[__NR_getpgid] = "getpgid";
#endif

#ifdef __NR_setfsuid
  syscallName[__NR_setfsuid] = "setfsuid";
#endif

#ifdef __NR_setfsgid
  syscallName[__NR_setfsgid] = "setfsgid";
#endif

#ifdef __NR_getsid
  syscallName[__NR_getsid] = "getsid";
#endif

#ifdef __NR_capget
  syscallName[__NR_capget] = "capget";
#endif

#ifdef __NR_capset
  syscallName[__NR_capset] = "capset";
#endif

#ifdef __NR_rt_sigpending
  syscallName[__NR_rt_sigpending] = "rt_sigpending";
#endif

#ifdef __NR_rt_sigtimedwait
  syscallName[__NR_rt_sigtimedwait] = "rt_sigtimedwait";
#endif

#ifdef __NR_rt_sigqueueinfo
  syscallName[__NR_rt_sigqueueinfo] = "rt_sigqueueinfo";
#endif

#ifdef __NR_rt_sigsuspend
  syscallName[__NR_rt_sigsuspend] = "rt_sigsuspend";
#endif

#ifdef __NR_sigaltstack
  syscallName[__NR_sigaltstack] = "sigaltstack";
#endif

#ifdef __NR_utime
  syscallName[__NR_utime] = "utime";
#endif

#ifdef __NR_mknod
  syscallName[__NR_mknod] = "mknod";
#endif

#ifdef __NR_uselib
  syscallName[__NR_uselib] = "uselib";
#endif

#ifdef __NR_personality
  syscallName[__NR_personality] = "personality";
#endif

#ifdef __NR_ustat
  syscallName[__NR_ustat] = "ustat";
#endif

#ifdef __NR_statfs
  syscallName[__NR_statfs] = "statfs";
#endif

#ifdef __NR_fstatfs
  syscallName[__NR_fstatfs] = "fstatfs";
#endif

#ifdef __NR_sysfs
  syscallName[__NR_sysfs] = "sysfs";
#endif

#ifdef __NR_getpriority
  syscallName[__NR_getpriority] = "getpriority";
#endif

#ifdef __NR_setpriority
  syscallName[__NR_setpriority] = "setpriority";
#endif

#ifdef __NR_sched_setparam
  syscallName[__NR_sched_setparam] = "sched_setparam";
#endif

#ifdef __NR_sched_getparam
  syscallName[__NR_sched_getparam] = "sched_getparam";
#endif

#ifdef __NR_sched_setscheduler
  syscallName[__NR_sched_setscheduler] = "sched_setscheduler";
#endif

#ifdef __NR_sched_getscheduler
  syscallName[__NR_sched_getscheduler] = "sched_getscheduler";
#endif

#ifdef __NR_sched_get_priority_max
  syscallName[__NR_sched_get_priority_max] = "sched_get_priority_max";
#endif

#ifdef __NR_sched_get_priority_min
  syscallName[__NR_sched_get_priority_min] = "sched_get_priority_min";
#endif

#ifdef __NR_sched_rr_get_interval
  syscallName[__NR_sched_rr_get_interval] = "sched_rr_get_interval";
#endif

#ifdef __NR_mlock
  syscallName[__NR_mlock] = "mlock";
#endif

#ifdef __NR_munlock
  syscallName[__NR_munlock] = "munlock";
#endif

#ifdef __NR_mlockall
  syscallName[__NR_mlockall] = "mlockall";
#endif

#ifdef __NR_munlockall
  syscallName[__NR_munlockall] = "munlockall";
#endif

#ifdef __NR_vhangup
  syscallName[__NR_vhangup] = "vhangup";
#endif

#ifdef __NR_modify_ldt
  syscallName[__NR_modify_ldt] = "modify_ldt";
#endif

#ifdef __NR_pivot_root
  syscallName[__NR_pivot_root] = "pivot_root";
#endif

#ifdef __NR__sysctl
  syscallName[__NR__sysctl] = "_sysctl";
#endif

#ifdef __NR_prctl
  syscallName[__NR_prctl] = "prctl";
#endif

#ifdef __NR_arch_prctl
  syscallName[__NR_arch_prctl] = "arch_prctl";
#endif

#ifdef __NR_adjtimex
  syscallName[__NR_adjtimex] = "adjtimex";
#endif

#ifdef __NR_setrlimit
  syscallName[__NR_setrlimit] = "setrlimit";
#endif

#ifdef __NR_chroot
  syscallName[__NR_chroot] = "chroot";
#endif

#ifdef __NR_sync
  syscallName[__NR_sync] = "sync";
#endif

#ifdef __NR_acct
  syscallName[__NR_acct] = "acct";
#endif

#ifdef __NR_settimeofday
  syscallName[__NR_settimeofday] = "settimeofday";
#endif

#ifdef __NR_mount
  syscallName[__NR_mount] = "mount";
#endif

#ifdef __NR_umount2
  syscallName[__NR_umount2] = "umount2";
#endif

#ifdef __NR_swapon
  syscallName[__NR_swapon] = "swapon";
#endif

#ifdef __NR_swapoff
  syscallName[__NR_swapoff] = "swapoff";
#endif

#ifdef __NR_reboot
  syscallName[__NR_reboot] = "reboot";
#endif

#ifdef __NR_sethostname
  syscallName[__NR_sethostname] = "sethostname";
#endif

#ifdef __NR_setdomainname
  syscallName[__NR_setdomainname] = "setdomainname";
#endif

#ifdef __NR_iopl
  syscallName[__NR_iopl] = "iopl";
#endif

#ifdef __NR_ioperm
  syscallName[__NR_ioperm] = "ioperm";
#endif

#ifdef __NR_create_module
  syscallName[__NR_create_module] = "create_module";
#endif

#ifdef __NR_init_module
  syscallName[__NR_init_module] = "init_module";
#endif

#ifdef __NR_delete_module
  syscallName[__NR_delete_module] = "delete_module";
#endif

#ifdef __NR_get_kernel_syms
  syscallName[__NR_get_kernel_syms] = "get_kernel_syms";
#endif

#ifdef __NR_query_module
  syscallName[__NR_query_module] = "query_module";
#endif

#ifdef __NR_quotactl
  syscallName[__NR_quotactl] = "quotactl";
#endif

#ifdef __NR_nfsservctl
  syscallName[__NR_nfsservctl] = "nfsservctl";
#endif

#ifdef __NR_getpmsg
  syscallName[__NR_getpmsg] = "getpmsg";
#endif

#ifdef __NR_putpmsg
  syscallName[__NR_putpmsg] = "putpmsg";
#endif

#ifdef __NR_afs_syscall
  syscallName[__NR_afs_syscall] = "afs_syscall";
#endif

#ifdef __NR_tuxcall
  syscallName[__NR_tuxcall] = "tuxcall";
#endif

#ifdef __NR_security
  syscallName[__NR_security] = "security";
#endif

#ifdef __NR_gettid
  syscallName[__NR_gettid] = "gettid";
#endif

#ifdef __NR_readahead
  syscallName[__NR_readahead] = "readahead";
#endif

#ifdef __NR_setxattr
  syscallName[__NR_setxattr] = "setxattr";
#endif

#ifdef __NR_lsetxattr
  syscallName[__NR_lsetxattr] = "lsetxattr";
#endif

#ifdef __NR_fsetxattr
  syscallName[__NR_fsetxattr] = "fsetxattr";
#endif

#ifdef __NR_getxattr
  syscallName[__NR_getxattr] = "getxattr";
#endif

#ifdef __NR_lgetxattr
  syscallName[__NR_lgetxattr] = "lgetxattr";
#endif

#ifdef __NR_fgetxattr
  syscallName[__NR_fgetxattr] = "fgetxattr";
#endif

#ifdef __NR_listxattr
  syscallName[__NR_listxattr] = "listxattr";
#endif

#ifdef __NR_llistxattr
  syscallName[__NR_llistxattr] = "llistxattr";
#endif

#ifdef __NR_flistxattr
  syscallName[__NR_flistxattr] = "flistxattr";
#endif

#ifdef __NR_removexattr
  syscallName[__NR_removexattr] = "removexattr";
#endif

#ifdef __NR_lremovexattr
  syscallName[__NR_lremovexattr] = "lremovexattr";
#endif

#ifdef __NR_fremovexattr
  syscallName[__NR_fremovexattr] = "fremovexattr";
#endif

#ifdef __NR_tkill
  syscallName[__NR_tkill] = "tkill";
#endif

#ifdef __NR_time
  syscallName[__NR_time] = "time";
#endif

#ifdef __NR_futex
  syscallName[__NR_futex] = "futex";
#endif

#ifdef __NR_sched_setaffinity
  syscallName[__NR_sched_setaffinity] = "sched_setaffinity";
#endif

#ifdef __NR_sched_getaffinity
  syscallName[__NR_sched_getaffinity] = "sched_getaffinity";
#endif

#ifdef __NR_set_thread_area
  syscallName[__NR_set_thread_area] = "set_thread_area";
#endif

#ifdef __NR_io_setup
  syscallName[__NR_io_setup] = "io_setup";
#endif

#ifdef __NR_io_destroy
  syscallName[__NR_io_destroy] = "io_destroy";
#endif

#ifdef __NR_io_getevents
  syscallName[__NR_io_getevents] = "io_getevents";
#endif

#ifdef __NR_io_submit
  syscallName[__NR_io_submit] = "io_submit";
#endif

#ifdef __NR_io_cancel
  syscallName[__NR_io_cancel] = "io_cancel";
#endif

#ifdef __NR_get_thread_area
  syscallName[__NR_get_thread_area] = "get_thread_area";
#endif

#ifdef __NR_lookup_dcookie
  syscallName[__NR_lookup_dcookie] = "lookup_dcookie";
#endif

#ifdef __NR_epoll_create
  syscallName[__NR_epoll_create] = "epoll_create";
#endif

#ifdef __NR_epoll_ctl_old
  syscallName[__NR_epoll_ctl_old] = "epoll_ctl_old";
#endif

#ifdef __NR_epoll_wait_old
  syscallName[__NR_epoll_wait_old] = "epoll_wait_old";
#endif

#ifdef __NR_remap_file_pages
  syscallName[__NR_remap_file_pages] = "remap_file_pages";
#endif

#ifdef __NR_getdents64
  syscallName[__NR_getdents64] = "getdents64";
#endif

#ifdef __NR_set_tid_address
  syscallName[__NR_set_tid_address] = "set_tid_address";
#endif

#ifdef __NR_restart_syscall
  syscallName[__NR_restart_syscall] = "restart_syscall";
#endif

#ifdef __NR_semtimedop
  syscallName[__NR_semtimedop] = "semtimedop";
#endif

#ifdef __NR_fadvise64
  syscallName[__NR_fadvise64] = "fadvise64";
#endif

#ifdef __NR_timer_create
  syscallName[__NR_timer_create] = "timer_create";
#endif

#ifdef __NR_timer_settime
  syscallName[__NR_timer_settime] = "timer_settime";
#endif

#ifdef __NR_timer_gettime
  syscallName[__NR_timer_gettime] = "timer_gettime";
#endif

#ifdef __NR_timer_getoverrun
  syscallName[__NR_timer_getoverrun] = "timer_getoverrun";
#endif

#ifdef __NR_timer_delete
  syscallName[__NR_timer_delete] = "timer_delete";
#endif

#ifdef __NR_clock_settime
  syscallName[__NR_clock_settime] = "clock_settime";
#endif

#ifdef __NR_clock_gettime
  syscallName[__NR_clock_gettime] = "clock_gettime";
#endif

#ifdef __NR_clock_getres
  syscallName[__NR_clock_getres] = "clock_getres";
#endif

#ifdef __NR_clock_nanosleep
  syscallName[__NR_clock_nanosleep] = "clock_nanosleep";
#endif

#ifdef __NR_exit_group
  syscallName[__NR_exit_group] = "exit_group";
#endif

#ifdef __NR_epoll_wait
  syscallName[__NR_epoll_wait] = "epoll_wait";
#endif

#ifdef __NR_epoll_ctl
  syscallName[__NR_epoll_ctl] = "epoll_ctl";
#endif

#ifdef __NR_tgkill
  syscallName[__NR_tgkill] = "tgkill";
#endif

#ifdef __NR_utimes
  syscallName[__NR_utimes] = "utimes";
#endif

#ifdef __NR_vserver
  syscallName[__NR_vserver] = "vserver";
#endif

#ifdef __NR_mbind
  syscallName[__NR_mbind] = "mbind";
#endif

#ifdef __NR_set_mempolicy
  syscallName[__NR_set_mempolicy] = "set_mempolicy";
#endif

#ifdef __NR_get_mempolicy
  syscallName[__NR_get_mempolicy] = "get_mempolicy";
#endif

#ifdef __NR_mq_open
  syscallName[__NR_mq_open] = "mq_open";
#endif

#ifdef __NR_mq_unlink
  syscallName[__NR_mq_unlink] = "mq_unlink";
#endif

#ifdef __NR_mq_timedsend
  syscallName[__NR_mq_timedsend] = "mq_timedsend";
#endif

#ifdef __NR_mq_timedreceive
  syscallName[__NR_mq_timedreceive] = "mq_timedreceive";
#endif

#ifdef __NR_mq_notify
  syscallName[__NR_mq_notify] = "mq_notify";
#endif

#ifdef __NR_mq_getsetattr
  syscallName[__NR_mq_getsetattr] = "mq_getsetattr";
#endif

#ifdef __NR_kexec_load
  syscallName[__NR_kexec_load] = "kexec_load";
#endif

#ifdef __NR_waitid
  syscallName[__NR_waitid] = "waitid";
#endif

#ifdef __NR_add_key
  syscallName[__NR_add_key] = "add_key";
#endif

#ifdef __NR_request_key
  syscallName[__NR_request_key] = "request_key";
#endif

#ifdef __NR_keyctl
  syscallName[__NR_keyctl] = "keyctl";
#endif

#ifdef __NR_ioprio_set
  syscallName[__NR_ioprio_set] = "ioprio_set";
#endif

#ifdef __NR_ioprio_get
  syscallName[__NR_ioprio_get] = "ioprio_get";
#endif

#ifdef __NR_inotify_init
  syscallName[__NR_inotify_init] = "inotify_init";
#endif

#ifdef __NR_inotify_add_watch
  syscallName[__NR_inotify_add_watch] = "inotify_add_watch";
#endif

#ifdef __NR_inotify_rm_watch
  syscallName[__NR_inotify_rm_watch] = "inotify_rm_watch";
#endif

#ifdef __NR_migrate_pages
  syscallName[__NR_migrate_pages] = "migrate_pages";
#endif

#ifdef __NR_openat
  syscallName[__NR_openat] = "openat";
#endif

#ifdef __NR_mkdirat
  syscallName[__NR_mkdirat] = "mkdirat";
#endif

#ifdef __NR_mknodat
  syscallName[__NR_mknodat] = "mknodat";
#endif

#ifdef __NR_fchownat
  syscallName[__NR_fchownat] = "fchownat";
#endif

#ifdef __NR_futimesat
  syscallName[__NR_futimesat] = "futimesat";
#endif

#ifdef __NR_newfstatat
  syscallName[__NR_newfstatat] = "newfstatat";
#endif

#ifdef __NR_unlinkat
  syscallName[__NR_unlinkat] = "unlinkat";
#endif

#ifdef __NR_renameat
  syscallName[__NR_renameat] = "renameat";
#endif

#ifdef __NR_linkat
  syscallName[__NR_linkat] = "linkat";
#endif

#ifdef __NR_symlinkat
  syscallName[__NR_symlinkat] = "symlinkat";
#endif

#ifdef __NR_readlinkat
  syscallName[__NR_readlinkat] = "readlinkat";
#endif

#ifdef __NR_fchmodat
  syscallName[__NR_fchmodat] = "fchmodat";
#endif

#ifdef __NR_faccessat
  syscallName[__NR_faccessat] = "faccessat";
#endif

#ifdef __NR_pselect6
  syscallName[__NR_pselect6] = "pselect6";
#endif

#ifdef __NR_ppoll
  syscallName[__NR_ppoll] = "ppoll";
#endif

#ifdef __NR_unshare
  syscallName[__NR_unshare] = "unshare";
#endif

#ifdef __NR_set_robust_list
  syscallName[__NR_set_robust_list] = "set_robust_list";
#endif

#ifdef __NR_get_robust_list
  syscallName[__NR_get_robust_list] = "get_robust_list";
#endif

#ifdef __NR_splice
  syscallName[__NR_splice] = "splice";
#endif

#ifdef __NR_tee
  syscallName[__NR_tee] = "tee";
#endif

#ifdef __NR_sync_file_range
  syscallName[__NR_sync_file_range] = "sync_file_range";
#endif

#ifdef __NR_vmsplice
  syscallName[__NR_vmsplice] = "vmsplice";
#endif

#ifdef __NR_move_pages
  syscallName[__NR_move_pages] = "move_pages";
#endif

#ifdef __NR_utimensat
  syscallName[__NR_utimensat] = "utimensat";
#endif

#ifdef __NR_epoll_pwait
  syscallName[__NR_epoll_pwait] = "epoll_pwait";
#endif

#ifdef __NR_signalfd
  syscallName[__NR_signalfd] = "signalfd";
#endif

#ifdef __NR_timerfd_create
  syscallName[__NR_timerfd_create] = "timerfd_create";
#endif

#ifdef __NR_eventfd
  syscallName[__NR_eventfd] = "eventfd";
#endif

#ifdef __NR_fallocate
  syscallName[__NR_fallocate] = "fallocate";
#endif

#ifdef __NR_timerfd_settime
  syscallName[__NR_timerfd_settime] = "timerfd_settime";
#endif

#ifdef __NR_timerfd_gettime
  syscallName[__NR_timerfd_gettime] = "timerfd_gettime";
#endif

#ifdef __NR_accept4
  syscallName[__NR_accept4] = "accept4";
#endif

#ifdef __NR_signalfd4
  syscallName[__NR_signalfd4] = "signalfd4";
#endif

#ifdef __NR_eventfd2
  syscallName[__NR_eventfd2] = "eventfd2";
#endif

#ifdef __NR_epoll_create1
  syscallName[__NR_epoll_create1] = "epoll_create1";
#endif

#ifdef __NR_dup3
  syscallName[__NR_dup3] = "dup3";
#endif

#ifdef __NR_pipe2
  syscallName[__NR_pipe2] = "pipe2";
#endif

#ifdef __NR_inotify_init1
  syscallName[__NR_inotify_init1] = "inotify_init1";
#endif

#ifdef __NR_preadv
  syscallName[__NR_preadv] = "preadv";
#endif

#ifdef __NR_pwritev
  syscallName[__NR_pwritev] = "pwritev";
#endif

#ifdef __NR_rt_tgsigqueueinfo
  syscallName[__NR_rt_tgsigqueueinfo] = "rt_tgsigqueueinfo";
#endif

#ifdef __NR_perf_event_open
  syscallName[__NR_perf_event_open] = "perf_event_open";
#endif

#ifdef __NR_recvmmsg
  syscallName[__NR_recvmmsg] = "recvmmsg";
#endif

#ifdef __NR_fanotify_init
  syscallName[__NR_fanotify_init] = "fanotify_init";
#endif

#ifdef __NR_fanotify_mark
  syscallName[__NR_fanotify_mark] = "fanotify_mark";
#endif

#ifdef __NR_prlimit64
  syscallName[__NR_prlimit64] = "prlimit64";
#endif

#ifdef __NR_name_to_handle_at
  syscallName[__NR_name_to_handle_at] = "name_to_handle_at";
#endif

#ifdef __NR_open_by_handle_at
  syscallName[__NR_open_by_handle_at] = "open_by_handle_at";
#endif

#ifdef __NR_clock_adjtime
  syscallName[__NR_clock_adjtime] = "clock_adjtime";
#endif

#ifdef __NR_syncfs
  syscallName[__NR_syncfs] = "syncfs";
#endif

#ifdef __NR_sendmmsg
  syscallName[__NR_sendmmsg] = "sendmmsg";
#endif

#ifdef __NR_setns
  syscallName[__NR_setns] = "setns";
#endif

#ifdef __NR_getcpu
  syscallName[__NR_getcpu] = "getcpu";
#endif

#ifdef __NR_process_vm_readv
  syscallName[__NR_process_vm_readv] = "process_vm_readv";
#endif

#ifdef __NR_process_vm_writev
  syscallName[__NR_process_vm_writev] = "process_vm_writev";
#endif

#ifdef __NR_kcmp
  syscallName[__NR_kcmp] = "kcmp";
#endif

#ifdef __NR_finit_module
  syscallName[__NR_finit_module] = "finit_module";
#endif

#ifdef __NR_sched_setattr
  syscallName[__NR_sched_setattr] = "sched_setattr";
#endif

#ifdef __NR_sched_getattr
  syscallName[__NR_sched_getattr] = "sched_getattr";
#endif

#ifdef __NR_renameat2
  syscallName[__NR_renameat2] = "renameat2";
#endif

#ifdef __NR_seccomp
  syscallName[__NR_seccomp] = "seccomp";
#endif

#ifdef __NR_getrandom
  syscallName[__NR_getrandom] = "getrandom";
#endif

#ifdef __NR_memfd_create
  syscallName[__NR_memfd_create] = "memfd_create";
#endif

#ifdef __NR_kexec_file_load
  syscallName[__NR_kexec_file_load] = "kexec_file_load";
#endif

#ifdef __NR_bpf
  syscallName[__NR_bpf] = "bpf";
#endif

#ifdef __NR_userfaultfd
  syscallName[__NR_userfaultfd] = "userfaultfd";
#endif

#ifdef __NR_membarrier
  syscallName[__NR_membarrier] = "membarrier";
#endif

#ifdef __NR_mlock2
  syscallName[__NR_mlock2] = "mlock2";
#endif

#ifdef __NR_copy_file_range
  syscallName[__NR_copy_file_range] = "copy_file_range";
#endif

#ifdef __NR_pkey_mprotect
  syscallName[__NR_pkey_mprotect] = "pkey_mprotect";
#endif

#ifdef __NR_pkey_alloc
  syscallName[__NR_pkey_alloc] = "pkey_alloc";
#endif

#ifdef __NR_pkey_free
  syscallName[__NR_pkey_free] = "pkey_free";
#endif
}
