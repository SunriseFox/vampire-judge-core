// 0 1 2 3
//safe, get, write, dangerous

#ifdef __NR_read // 0
  syscallName[__NR_read] = "read";
#endif

#ifdef __NR_write // 0
  syscallName[__NR_write] = "write";
#endif

#ifdef __NR_open // 2
  syscallName[__NR_open] = "open";
#endif

#ifdef __NR_close // 0
  syscallName[__NR_close] = "close";
#endif

#ifdef __NR_stat // 1
  syscallName[__NR_stat] = "stat";
#endif

#ifdef __NR_fstat // 0, get information of opened filess
  syscallName[__NR_fstat] = "fstat";
#endif

#ifdef __NR_lstat // 1
  syscallName[__NR_lstat] = "lstat";
#endif

#ifdef __NR_poll // 0
  syscallName[__NR_poll] = "poll";
#endif

#ifdef __NR_lseek // 0
  syscallName[__NR_lseek] = "lseek";
#endif

#ifdef __NR_mmap // 0
  syscallName[__NR_mmap] = "mmap";
#endif

#ifdef __NR_mprotect // 0
  syscallName[__NR_mprotect] = "mprotect";
#endif

#ifdef __NR_munmap // 0
  syscallName[__NR_munmap] = "munmap";
#endif

#ifdef __NR_brk // 0
  syscallName[__NR_brk] = "brk";
#endif

#ifdef __NR_rt_sigaction // 0
  syscallName[__NR_rt_sigaction] = "rt_sigaction";
#endif

#ifdef __NR_rt_sigprocmask // 0
  syscallName[__NR_rt_sigprocmask] = "rt_sigprocmask";
#endif

#ifdef __NR_rt_sigreturn // 0
  syscallName[__NR_rt_sigreturn] = "rt_sigreturn";
#endif

#ifdef __NR_ioctl // 3
  syscallName[__NR_ioctl] = "ioctl";
#endif

#ifdef __NR_pread64 // 0
  syscallName[__NR_pread64] = "pread64";
#endif

#ifdef __NR_pwrite64 // 0
  syscallName[__NR_pwrite64] = "pwrite64";
#endif

#ifdef __NR_readv // 1
  syscallName[__NR_readv] = "readv";
#endif

#ifdef __NR_writev // 1
  syscallName[__NR_writev] = "writev";
#endif

#ifdef __NR_access // 0
  syscallName[__NR_access] = "access";
#endif

#ifdef __NR_pipe // 0
  syscallName[__NR_pipe] = "pipe";
#endif

#ifdef __NR_select // 0
  syscallName[__NR_select] = "select";
#endif

#ifdef __NR_sched_yield // 1 should not be called, maybe
  syscallName[__NR_sched_yield] = "sched_yield";
#endif

#ifdef __NR_mremap // 0
  syscallName[__NR_mremap] = "mremap";
#endif

#ifdef __NR_msync // 0
  syscallName[__NR_msync] = "msync";
#endif

#ifdef __NR_mincore // 0
  syscallName[__NR_mincore] = "mincore";
#endif

#ifdef __NR_madvise // 0
  syscallName[__NR_madvise] = "madvise";
#endif

#ifdef __NR_shmget // 1
  syscallName[__NR_shmget] = "shmget";
#endif

#ifdef __NR_shmat // 1
  syscallName[__NR_shmat] = "shmat";
#endif

#ifdef __NR_shmctl // 1
  syscallName[__NR_shmctl] = "shmctl";
#endif

#ifdef __NR_dup  // 1
  syscallName[__NR_dup] = "dup";
#endif

#ifdef __NR_dup2 // 1
  syscallName[__NR_dup2] = "dup2";
#endif

#ifdef __NR_pause // 0
  syscallName[__NR_pause] = "pause";
#endif

#ifdef __NR_nanosleep // 0
  syscallName[__NR_nanosleep] = "nanosleep";
#endif

#ifdef __NR_getitimer // 1 get internal timer
  syscallName[__NR_getitimer] = "getitimer";
#endif

#ifdef __NR_alarm // 0
  syscallName[__NR_alarm] = "alarm";
#endif

#ifdef __NR_setitimer // 1 set internal timer
  syscallName[__NR_setitimer] = "setitimer";
#endif

#ifdef __NR_getpid // 0
  syscallName[__NR_getpid] = "getpid";
#endif

#ifdef __NR_sendfile // 1 copy one file to another
  syscallName[__NR_sendfile] = "sendfile";
#endif

#ifdef __NR_socket // 2 maybe used by unix socket
  syscallName[__NR_socket] = "socket";
#endif

#ifdef __NR_connect // 2
  syscallName[__NR_connect] = "connect";
#endif

#ifdef __NR_accept // 3
  syscallName[__NR_accept] = "accept";
#endif

#ifdef __NR_sendto // 3
  syscallName[__NR_sendto] = "sendto";
#endif

#ifdef __NR_recvfrom // 3
  syscallName[__NR_recvfrom] = "recvfrom";
#endif

#ifdef __NR_sendmsg // 3
  syscallName[__NR_sendmsg] = "sendmsg";
#endif

#ifdef __NR_recvmsg // 3
  syscallName[__NR_recvmsg] = "recvmsg";
#endif

#ifdef __NR_shutdown // 3
  syscallName[__NR_shutdown] = "shutdown";
#endif

#ifdef __NR_bind // 3
  syscallName[__NR_bind] = "bind";
#endif

#ifdef __NR_listen // 3
  syscallName[__NR_listen] = "listen";
#endif

#ifdef __NR_getsockname // 3
  syscallName[__NR_getsockname] = "getsockname";
#endif

#ifdef __NR_getpeername // 3
  syscallName[__NR_getpeername] = "getpeername";
#endif

#ifdef __NR_socketpair // 3
  syscallName[__NR_socketpair] = "socketpair";
#endif

#ifdef __NR_setsockopt // 3
  syscallName[__NR_setsockopt] = "setsockopt";
#endif

#ifdef __NR_getsockopt // 3
  syscallName[__NR_getsockopt] = "getsockopt";
#endif

#ifdef __NR_clone // 1
  syscallName[__NR_clone] = "clone";
#endif

#ifdef __NR_fork // 1
  syscallName[__NR_fork] = "fork";
#endif

#ifdef __NR_vfork // 1
  syscallName[__NR_vfork] = "vfork";
#endif

#ifdef __NR_execve // 1
  syscallName[__NR_execve] = "execve";
#endif

#ifdef __NR_exit // 0
  syscallName[__NR_exit] = "exit";
#endif

#ifdef __NR_wait4 // 0
  syscallName[__NR_wait4] = "wait4";
#endif

#ifdef __NR_kill // 1
  syscallName[__NR_kill] = "kill";
#endif

#ifdef __NR_uname // 0
  syscallName[__NR_uname] = "uname";
#endif

#ifdef __NR_semget // 1 ipc
  syscallName[__NR_semget] = "semget";
#endif

#ifdef __NR_semop // 1 ipc
  syscallName[__NR_semop] = "semop";
#endif

#ifdef __NR_semctl // 1 ipc
  syscallName[__NR_semctl] = "semctl";
#endif

#ifdef __NR_shmdt // 1 ipc
  syscallName[__NR_shmdt] = "shmdt";
#endif

#ifdef __NR_msgget // 1 ipc
  syscallName[__NR_msgget] = "msgget";
#endif

#ifdef __NR_msgsnd // 1 ipc
  syscallName[__NR_msgsnd] = "msgsnd";
#endif

#ifdef __NR_msgrcv // 1 ipc
  syscallName[__NR_msgrcv] = "msgrcv";
#endif

#ifdef __NR_msgctl // 1 ipc
  syscallName[__NR_msgctl] = "msgctl";
#endif

#ifdef __NR_fcntl // 1 cannot update open mode
  syscallName[__NR_fcntl] = "fcntl";
#endif

#ifdef __NR_flock // 1
  syscallName[__NR_flock] = "flock";
#endif

#ifdef __NR_fsync // 1
  syscallName[__NR_fsync] = "fsync";
#endif

#ifdef __NR_fdatasync // 1
  syscallName[__NR_fdatasync] = "fdatasync";
#endif

#ifdef __NR_truncate // 2 could truncate any file, but as all owned by root ,it might be ok
  syscallName[__NR_truncate] = "truncate";
#endif

#ifdef __NR_ftruncate // 1
  syscallName[__NR_ftruncate] = "ftruncate";
#endif

#ifdef __NR_getdents // 2 should not be called by user
  syscallName[__NR_getdents] = "getdents";
#endif

#ifdef __NR_getcwd // 0
  syscallName[__NR_getcwd] = "getcwd";
#endif

#ifdef __NR_chdir // 2
  syscallName[__NR_chdir] = "chdir";
#endif

#ifdef __NR_fchdir // 1
  syscallName[__NR_fchdir] = "fchdir";
#endif

#ifdef __NR_rename // 2
  syscallName[__NR_rename] = "rename";
#endif

#ifdef __NR_mkdir // 2
  syscallName[__NR_mkdir] = "mkdir";
#endif

#ifdef __NR_rmdir // 2
  syscallName[__NR_rmdir] = "rmdir";
#endif

#ifdef __NR_creat // 2
  syscallName[__NR_creat] = "creat";
#endif

#ifdef __NR_link // 2
  syscallName[__NR_link] = "link";
#endif

#ifdef __NR_unlink // 2
  syscallName[__NR_unlink] = "unlink";
#endif

#ifdef __NR_symlink // 2
  syscallName[__NR_symlink] = "symlink";
#endif

#ifdef __NR_readlink // 1
  syscallName[__NR_readlink] = "readlink";
#endif

#ifdef __NR_chmod // 2
  syscallName[__NR_chmod] = "chmod";
#endif

#ifdef __NR_fchmod // 1
  syscallName[__NR_fchmod] = "fchmod";
#endif

#ifdef __NR_chown // 2
  syscallName[__NR_chown] = "chown";
#endif

#ifdef __NR_fchown // 1
  syscallName[__NR_fchown] = "fchown";
#endif

#ifdef __NR_lchown // 2
  syscallName[__NR_lchown] = "lchown";
#endif

#ifdef __NR_umask // 1
  syscallName[__NR_umask] = "umask";
#endif

#ifdef __NR_gettimeofday // 0
  syscallName[__NR_gettimeofday] = "gettimeofday";
#endif

#ifdef __NR_getrlimit // 0
  syscallName[__NR_getrlimit] = "getrlimit";
#endif

#ifdef __NR_getrusage // 0
  syscallName[__NR_getrusage] = "getrusage";
#endif

#ifdef __NR_sysinfo // 1
  syscallName[__NR_sysinfo] = "sysinfo";
#endif

#ifdef __NR_times // 1
  syscallName[__NR_times] = "times";
#endif

#ifdef __NR_ptrace // 3
  syscallName[__NR_ptrace] = "ptrace";
#endif

#ifdef __NR_getuid // 0
  syscallName[__NR_getuid] = "getuid";
#endif

#ifdef __NR_syslog // 3
  syscallName[__NR_syslog] = "syslog";
#endif

#ifdef __NR_getgid // 0
  syscallName[__NR_getgid] = "getgid";
#endif

#ifdef __NR_setuid // 3
  syscallName[__NR_setuid] = "setuid";
#endif

#ifdef __NR_setgid // 3
  syscallName[__NR_setgid] = "setgid";
#endif

#ifdef __NR_geteuid // 0
  syscallName[__NR_geteuid] = "geteuid";
#endif

#ifdef __NR_getegid // 0
  syscallName[__NR_getegid] = "getegid";
#endif

#ifdef __NR_setpgid // 3
  syscallName[__NR_setpgid] = "setpgid";
#endif

#ifdef __NR_getppid // 0
  syscallName[__NR_getppid] = "getppid";
#endif

#ifdef __NR_getpgrp // 0
  syscallName[__NR_getpgrp] = "getpgrp";
#endif

#ifdef __NR_setsid // 3
  syscallName[__NR_setsid] = "setsid";
#endif

#ifdef __NR_setreuid // 3
  syscallName[__NR_setreuid] = "setreuid";
#endif

#ifdef __NR_setregid // 3
  syscallName[__NR_setregid] = "setregid";
#endif

#ifdef __NR_getgroups // 0
  syscallName[__NR_getgroups] = "getgroups";
#endif

#ifdef __NR_setgroups // 3
  syscallName[__NR_setgroups] = "setgroups";
#endif

#ifdef __NR_setresuid // 3
  syscallName[__NR_setresuid] = "setresuid";
#endif

#ifdef __NR_getresuid // 0
  syscallName[__NR_getresuid] = "getresuid";
#endif

#ifdef __NR_setresgid // 3
  syscallName[__NR_setresgid] = "setresgid";
#endif

#ifdef __NR_getresgid // 0
  syscallName[__NR_getresgid] = "getresgid";
#endif

#ifdef __NR_getpgid // 0
  syscallName[__NR_getpgid] = "getpgid";
#endif

#ifdef __NR_setfsuid // 3
  syscallName[__NR_setfsuid] = "setfsuid";
#endif

#ifdef __NR_setfsgid // 3
  syscallName[__NR_setfsgid] = "setfsgid";
#endif

#ifdef __NR_getsid // 0
  syscallName[__NR_getsid] = "getsid";
#endif

#ifdef __NR_capget // 3
  syscallName[__NR_capget] = "capget";
#endif

#ifdef __NR_capset // 3
  syscallName[__NR_capset] = "capset";
#endif

#ifdef __NR_rt_sigpending // 0
  syscallName[__NR_rt_sigpending] = "rt_sigpending";
#endif

#ifdef __NR_rt_sigtimedwait // 0
  syscallName[__NR_rt_sigtimedwait] = "rt_sigtimedwait";
#endif

#ifdef __NR_rt_sigqueueinfo // 0
  syscallName[__NR_rt_sigqueueinfo] = "rt_sigqueueinfo";
#endif

#ifdef __NR_rt_sigsuspend // 0
  syscallName[__NR_rt_sigsuspend] = "rt_sigsuspend";
#endif

#ifdef __NR_sigaltstack // 0
  syscallName[__NR_sigaltstack] = "sigaltstack";
#endif

#ifdef __NR_utime  // 2
  syscallName[__NR_utime] = "utime";
#endif

#ifdef __NR_mknod  // 2
  syscallName[__NR_mknod] = "mknod";
#endif

#ifdef __NR_uselib  // 2 as not used by glibc
  syscallName[__NR_uselib] = "uselib";
#endif

#ifdef __NR_personality  // 2
  syscallName[__NR_personality] = "personality";
#endif

#ifdef __NR_ustat // 2
  syscallName[__NR_ustat] = "ustat";
#endif

#ifdef __NR_statfs // 2
  syscallName[__NR_statfs] = "statfs";
#endif

#ifdef __NR_fstatfs // 0
  syscallName[__NR_fstatfs] = "fstatfs";
#endif

#ifdef __NR_sysfs // 0
  syscallName[__NR_sysfs] = "sysfs";
#endif

#ifdef __NR_getpriority // 0
  syscallName[__NR_getpriority] = "getpriority";
#endif

#ifdef __NR_setpriority // 3
  syscallName[__NR_setpriority] = "setpriority";
#endif

#ifdef __NR_sched_setparam // 3
  syscallName[__NR_sched_setparam] = "sched_setparam";
#endif

#ifdef __NR_sched_getparam // 0
  syscallName[__NR_sched_getparam] = "sched_getparam";
#endif

#ifdef __NR_sched_setscheduler // 3
  syscallName[__NR_sched_setscheduler] = "sched_setscheduler";
#endif

#ifdef __NR_sched_getscheduler // 0
  syscallName[__NR_sched_getscheduler] = "sched_getscheduler";
#endif

#ifdef __NR_sched_get_priority_max // 0
  syscallName[__NR_sched_get_priority_max] = "sched_get_priority_max";
#endif

#ifdef __NR_sched_get_priority_min // 0
  syscallName[__NR_sched_get_priority_min] = "sched_get_priority_min";
#endif

#ifdef __NR_sched_rr_get_interval // 0
  syscallName[__NR_sched_rr_get_interval] = "sched_rr_get_interval";
#endif

#ifdef __NR_mlock // 1
  syscallName[__NR_mlock] = "mlock";
#endif

#ifdef __NR_munlock // 1
  syscallName[__NR_munlock] = "munlock";
#endif

#ifdef __NR_mlockall // 1
  syscallName[__NR_mlockall] = "mlockall";
#endif

#ifdef __NR_munlockall // 1
  syscallName[__NR_munlockall] = "munlockall";
#endif

#ifdef __NR_vhangup // 2
  syscallName[__NR_vhangup] = "vhangup";
#endif

#ifdef __NR_modify_ldt // 3
  syscallName[__NR_modify_ldt] = "modify_ldt";
#endif

#ifdef __NR_pivot_root // 3
  syscallName[__NR_pivot_root] = "pivot_root";
#endif

#ifdef __NR__sysctl // 3
  syscallName[__NR__sysctl] = "_sysctl";
#endif

#ifdef __NR_prctl // 1
  syscallName[__NR_prctl] = "prctl";
#endif

#ifdef __NR_arch_prctl // 1
  syscallName[__NR_arch_prctl] = "arch_prctl";
#endif

#ifdef __NR_adjtimex // 3
  syscallName[__NR_adjtimex] = "adjtimex";
#endif

#ifdef __NR_setrlimit // 3
  syscallName[__NR_setrlimit] = "setrlimit";
#endif

#ifdef __NR_chroot // 3
  syscallName[__NR_chroot] = "chroot";
#endif

#ifdef __NR_sync // 1
  syscallName[__NR_sync] = "sync";
#endif

#ifdef __NR_acct // 3
  syscallName[__NR_acct] = "acct";
#endif

#ifdef __NR_settimeofday // 3
  syscallName[__NR_settimeofday] = "settimeofday";
#endif

#ifdef __NR_mount // 3
  syscallName[__NR_mount] = "mount";
#endif

#ifdef __NR_umount2 // 3
  syscallName[__NR_umount2] = "umount2";
#endif

#ifdef __NR_swapon // 3
  syscallName[__NR_swapon] = "swapon";
#endif

#ifdef __NR_swapoff // 3
  syscallName[__NR_swapoff] = "swapoff";
#endif

#ifdef __NR_reboot // 3
  syscallName[__NR_reboot] = "reboot";
#endif

#ifdef __NR_sethostname // 3
  syscallName[__NR_sethostname] = "sethostname";
#endif

#ifdef __NR_setdomainname // 3
  syscallName[__NR_setdomainname] = "setdomainname";
#endif

#ifdef __NR_iopl // 3
  syscallName[__NR_iopl] = "iopl";
#endif

#ifdef __NR_ioperm // 3
  syscallName[__NR_ioperm] = "ioperm";
#endif

#ifdef __NR_create_module // 3
  syscallName[__NR_create_module] = "create_module";
#endif

#ifdef __NR_init_module // 3
  syscallName[__NR_init_module] = "init_module";
#endif

#ifdef __NR_delete_module // 3
  syscallName[__NR_delete_module] = "delete_module";
#endif

#ifdef __NR_get_kernel_syms // 3
  syscallName[__NR_get_kernel_syms] = "get_kernel_syms";
#endif

#ifdef __NR_query_module // 3
  syscallName[__NR_query_module] = "query_module";
#endif

#ifdef __NR_quotactl // 3
  syscallName[__NR_quotactl] = "quotactl";
#endif

#ifdef __NR_nfsservctl // 3
  syscallName[__NR_nfsservctl] = "nfsservctl";
#endif

#ifdef __NR_getpmsg // 3 not used
  syscallName[__NR_getpmsg] = "getpmsg";
#endif

#ifdef __NR_putpmsg // 3 not used
  syscallName[__NR_putpmsg] = "putpmsg";
#endif

#ifdef __NR_afs_syscall // 3 not used
  syscallName[__NR_afs_syscall] = "afs_syscall";
#endif

#ifdef __NR_tuxcall // 3 not used
  syscallName[__NR_tuxcall] = "tuxcall";
#endif

#ifdef __NR_security // 3 not used
  syscallName[__NR_security] = "security";
#endif

#ifdef __NR_gettid // 0
  syscallName[__NR_gettid] = "gettid";
#endif

#ifdef __NR_readahead // 0
  syscallName[__NR_readahead] = "readahead";
#endif

#ifdef __NR_setxattr // 2
  syscallName[__NR_setxattr] = "setxattr";
#endif

#ifdef __NR_lsetxattr // 2
  syscallName[__NR_lsetxattr] = "lsetxattr";
#endif

#ifdef __NR_fsetxattr // 1
  syscallName[__NR_fsetxattr] = "fsetxattr";
#endif

#ifdef __NR_getxattr // 0
  syscallName[__NR_getxattr] = "getxattr";
#endif

#ifdef __NR_lgetxattr // 0
  syscallName[__NR_lgetxattr] = "lgetxattr";
#endif

#ifdef __NR_fgetxattr // 0
  syscallName[__NR_fgetxattr] = "fgetxattr";
#endif

#ifdef __NR_listxattr // 0
  syscallName[__NR_listxattr] = "listxattr";
#endif

#ifdef __NR_llistxattr // 0
  syscallName[__NR_llistxattr] = "llistxattr";
#endif

#ifdef __NR_flistxattr // 0
  syscallName[__NR_flistxattr] = "flistxattr";
#endif

#ifdef __NR_removexattr // 2
  syscallName[__NR_removexattr] = "removexattr";
#endif

#ifdef __NR_lremovexattr // 2
  syscallName[__NR_lremovexattr] = "lremovexattr";
#endif

#ifdef __NR_fremovexattr // 1
  syscallName[__NR_fremovexattr] = "fremovexattr";
#endif

#ifdef __NR_tkill // 1
  syscallName[__NR_tkill] = "tkill";
#endif

#ifdef __NR_time // 0
  syscallName[__NR_time] = "time";
#endif

#ifdef __NR_futex // 1
  syscallName[__NR_futex] = "futex";
#endif

#ifdef __NR_sched_setaffinity // 1
  syscallName[__NR_sched_setaffinity] = "sched_setaffinity";
#endif

#ifdef __NR_sched_getaffinity // 1
  syscallName[__NR_sched_getaffinity] = "sched_getaffinity";
#endif

#ifdef __NR_set_thread_area // 1
  syscallName[__NR_set_thread_area] = "set_thread_area";
#endif

#ifdef __NR_io_setup // 3
  syscallName[__NR_io_setup] = "io_setup";
#endif

#ifdef __NR_io_destroy // 3
  syscallName[__NR_io_destroy] = "io_destroy";
#endif

#ifdef __NR_io_getevents // 3
  syscallName[__NR_io_getevents] = "io_getevents";
#endif

#ifdef __NR_io_submit // 3
  syscallName[__NR_io_submit] = "io_submit";
#endif

#ifdef __NR_io_cancel // 3
  syscallName[__NR_io_cancel] = "io_cancel";
#endif

#ifdef __NR_get_thread_area // 1
  syscallName[__NR_get_thread_area] = "get_thread_area";
#endif

#ifdef __NR_lookup_dcookie // 1
  syscallName[__NR_lookup_dcookie] = "lookup_dcookie";
#endif

#ifdef __NR_epoll_create // 1
  syscallName[__NR_epoll_create] = "epoll_create";
#endif

#ifdef __NR_epoll_ctl_old // 1
  syscallName[__NR_epoll_ctl_old] = "epoll_ctl_old";
#endif

#ifdef __NR_epoll_wait_old // 1
  syscallName[__NR_epoll_wait_old] = "epoll_wait_old";
#endif

#ifdef __NR_remap_file_pages // 1
  syscallName[__NR_remap_file_pages] = "remap_file_pages";
#endif

#ifdef __NR_getdents64 // 1
  syscallName[__NR_getdents64] = "getdents64";
#endif

#ifdef __NR_set_tid_address // 2
  syscallName[__NR_set_tid_address] = "set_tid_address";
#endif

#ifdef __NR_restart_syscall // 1
  syscallName[__NR_restart_syscall] = "restart_syscall";
#endif

#ifdef __NR_semtimedop // 2
  syscallName[__NR_semtimedop] = "semtimedop";
#endif

#ifdef __NR_fadvise64 // 1
  syscallName[__NR_fadvise64] = "fadvise64";
#endif

#ifdef __NR_timer_create // 1
  syscallName[__NR_timer_create] = "timer_create";
#endif

#ifdef __NR_timer_settime // 1
  syscallName[__NR_timer_settime] = "timer_settime";
#endif

#ifdef __NR_timer_gettime // 1
  syscallName[__NR_timer_gettime] = "timer_gettime";
#endif

#ifdef __NR_timer_getoverrun // 1
  syscallName[__NR_timer_getoverrun] = "timer_getoverrun";
#endif

#ifdef __NR_timer_delete // 1
  syscallName[__NR_timer_delete] = "timer_delete";
#endif

#ifdef __NR_clock_settime // 1
  syscallName[__NR_clock_settime] = "clock_settime";
#endif

#ifdef __NR_clock_gettime // 1
  syscallName[__NR_clock_gettime] = "clock_gettime";
#endif

#ifdef __NR_clock_getres // 1
  syscallName[__NR_clock_getres] = "clock_getres";
#endif

#ifdef __NR_clock_nanosleep // 1
  syscallName[__NR_clock_nanosleep] = "clock_nanosleep";
#endif

#ifdef __NR_exit_group // 0
  syscallName[__NR_exit_group] = "exit_group";
#endif

#ifdef __NR_epoll_wait // 1
  syscallName[__NR_epoll_wait] = "epoll_wait";
#endif

#ifdef __NR_epoll_ctl // 1
  syscallName[__NR_epoll_ctl] = "epoll_ctl";
#endif

#ifdef __NR_tgkill // 1
  syscallName[__NR_tgkill] = "tgkill";
#endif

#ifdef __NR_utimes // 2
  syscallName[__NR_utimes] = "utimes";
#endif

#ifdef __NR_vserver // 3 not implemented
  syscallName[__NR_vserver] = "vserver";
#endif

#ifdef __NR_mbind // 3 won't link
  syscallName[__NR_mbind] = "mbind";
#endif

#ifdef __NR_set_mempolicy // 3 won't link
  syscallName[__NR_set_mempolicy] = "set_mempolicy";
#endif

#ifdef __NR_get_mempolicy // 3 won't link
  syscallName[__NR_get_mempolicy] = "get_mempolicy";
#endif

#ifdef __NR_mq_open // 3 won't link
  syscallName[__NR_mq_open] = "mq_open";
#endif

#ifdef __NR_mq_unlink // 3 won't link
  syscallName[__NR_mq_unlink] = "mq_unlink";
#endif

#ifdef __NR_mq_timedsend // 3 won't link
  syscallName[__NR_mq_timedsend] = "mq_timedsend";
#endif

#ifdef __NR_mq_timedreceive // 3 won't link
  syscallName[__NR_mq_timedreceive] = "mq_timedreceive";
#endif

#ifdef __NR_mq_notify // 3 won't link
  syscallName[__NR_mq_notify] = "mq_notify";
#endif

#ifdef __NR_mq_getsetattr // 3 won't link
  syscallName[__NR_mq_getsetattr] = "mq_getsetattr";
#endif

#ifdef __NR_kexec_load // 3
  syscallName[__NR_kexec_load] = "kexec_load";
#endif

#ifdef __NR_waitid // 1
  syscallName[__NR_waitid] = "waitid";
#endif

#ifdef __NR_add_key // 3
  syscallName[__NR_add_key] = "add_key";
#endif

#ifdef __NR_request_key // 3
  syscallName[__NR_request_key] = "request_key";
#endif

#ifdef __NR_keyctl // 3
  syscallName[__NR_keyctl] = "keyctl";
#endif

#ifdef __NR_ioprio_set // 3
  syscallName[__NR_ioprio_set] = "ioprio_set";
#endif

#ifdef __NR_ioprio_get // 3
  syscallName[__NR_ioprio_get] = "ioprio_get";
#endif

#ifdef __NR_inotify_init // 1
  syscallName[__NR_inotify_init] = "inotify_init";
#endif

#ifdef __NR_inotify_add_watch // 1
  syscallName[__NR_inotify_add_watch] = "inotify_add_watch";
#endif

#ifdef __NR_inotify_rm_watch // 1
  syscallName[__NR_inotify_rm_watch] = "inotify_rm_watch";
#endif

#ifdef __NR_migrate_pages // 3
  syscallName[__NR_migrate_pages] = "migrate_pages";
#endif

#ifdef __NR_openat // 2
  syscallName[__NR_openat] = "openat";
#endif

#ifdef __NR_mkdirat // 2
  syscallName[__NR_mkdirat] = "mkdirat";
#endif

#ifdef __NR_mknodat // 2
  syscallName[__NR_mknodat] = "mknodat";
#endif

#ifdef __NR_fchownat // 2
  syscallName[__NR_fchownat] = "fchownat";
#endif

#ifdef __NR_futimesat // 2
  syscallName[__NR_futimesat] = "futimesat";
#endif

#ifdef __NR_newfstatat // 2
  syscallName[__NR_newfstatat] = "newfstatat";
#endif

#ifdef __NR_unlinkat // 2
  syscallName[__NR_unlinkat] = "unlinkat";
#endif

#ifdef __NR_renameat // 2
  syscallName[__NR_renameat] = "renameat";
#endif

#ifdef __NR_linkat // 2
  syscallName[__NR_linkat] = "linkat";
#endif

#ifdef __NR_symlinkat // 2
  syscallName[__NR_symlinkat] = "symlinkat";
#endif

#ifdef __NR_readlinkat // 2
  syscallName[__NR_readlinkat] = "readlinkat";
#endif

#ifdef __NR_fchmodat // 2
  syscallName[__NR_fchmodat] = "fchmodat";
#endif

#ifdef __NR_faccessat // 2
  syscallName[__NR_faccessat] = "faccessat";
#endif

#ifdef __NR_pselect6 // 1
  syscallName[__NR_pselect6] = "pselect6";
#endif

#ifdef __NR_ppoll // 1
  syscallName[__NR_ppoll] = "ppoll";
#endif

#ifdef __NR_unshare // 3
  syscallName[__NR_unshare] = "unshare";
#endif

#ifdef __NR_set_robust_list // 1
  syscallName[__NR_set_robust_list] = "set_robust_list";
#endif

#ifdef __NR_get_robust_list // 1
  syscallName[__NR_get_robust_list] = "get_robust_list";
#endif

#ifdef __NR_splice // 1
  syscallName[__NR_splice] = "splice";
#endif

#ifdef __NR_tee // 1
  syscallName[__NR_tee] = "tee";
#endif

#ifdef __NR_sync_file_range // 1
  syscallName[__NR_sync_file_range] = "sync_file_range";
#endif

#ifdef __NR_vmsplice // 1
  syscallName[__NR_vmsplice] = "vmsplice";
#endif

#ifdef __NR_move_pages // 3
  syscallName[__NR_move_pages] = "move_pages";
#endif

#ifdef __NR_utimensat // 3
  syscallName[__NR_utimensat] = "utimensat";
#endif

#ifdef __NR_epoll_pwait // 1
  syscallName[__NR_epoll_pwait] = "epoll_pwait";
#endif

#ifdef __NR_signalfd // 1
  syscallName[__NR_signalfd] = "signalfd";
#endif

#ifdef __NR_timerfd_create // 1
  syscallName[__NR_timerfd_create] = "timerfd_create";
#endif

#ifdef __NR_eventfd // 1
  syscallName[__NR_eventfd] = "eventfd";
#endif

#ifdef __NR_fallocate // 1
  syscallName[__NR_fallocate] = "fallocate";
#endif

#ifdef __NR_timerfd_settime // 1
  syscallName[__NR_timerfd_settime] = "timerfd_settime";
#endif

#ifdef __NR_timerfd_gettime // 1
  syscallName[__NR_timerfd_gettime] = "timerfd_gettime";
#endif

#ifdef __NR_accept4 // 2
  syscallName[__NR_accept4] = "accept4";
#endif

#ifdef __NR_signalfd4 // 1
  syscallName[__NR_signalfd4] = "signalfd4";
#endif

#ifdef __NR_eventfd2 // 1
  syscallName[__NR_eventfd2] = "eventfd2";
#endif

#ifdef __NR_epoll_create1 // 1
  syscallName[__NR_epoll_create1] = "epoll_create1";
#endif

#ifdef __NR_dup3 // 1
  syscallName[__NR_dup3] = "dup3";
#endif

#ifdef __NR_pipe2 // 1
  syscallName[__NR_pipe2] = "pipe2";
#endif

#ifdef __NR_inotify_init1 // 1
  syscallName[__NR_inotify_init1] = "inotify_init1";
#endif

#ifdef __NR_preadv // 1
  syscallName[__NR_preadv] = "preadv";
#endif

#ifdef __NR_pwritev // 1
  syscallName[__NR_pwritev] = "pwritev";
#endif

#ifdef __NR_rt_tgsigqueueinfo // 1
  syscallName[__NR_rt_tgsigqueueinfo] = "rt_tgsigqueueinfo";
#endif

#ifdef __NR_perf_event_open // 3
  syscallName[__NR_perf_event_open] = "perf_event_open";
#endif

#ifdef __NR_recvmmsg // 2
  syscallName[__NR_recvmmsg] = "recvmmsg";
#endif

#ifdef __NR_fanotify_init // 1
  syscallName[__NR_fanotify_init] = "fanotify_init";
#endif

#ifdef __NR_fanotify_mark // 1
  syscallName[__NR_fanotify_mark] = "fanotify_mark";
#endif

#ifdef __NR_prlimit64 // 2
  syscallName[__NR_prlimit64] = "prlimit64";
#endif

#ifdef __NR_name_to_handle_at // 3
  syscallName[__NR_name_to_handle_at] = "name_to_handle_at";
#endif

#ifdef __NR_open_by_handle_at // 3
  syscallName[__NR_open_by_handle_at] = "open_by_handle_at";
#endif

#ifdef __NR_clock_adjtime // 3
  syscallName[__NR_clock_adjtime] = "clock_adjtime";
#endif

#ifdef __NR_syncfs // 1
  syscallName[__NR_syncfs] = "syncfs";
#endif

#ifdef __NR_sendmmsg // 1
  syscallName[__NR_sendmmsg] = "sendmmsg";
#endif

#ifdef __NR_setns // 3
  syscallName[__NR_setns] = "setns";
#endif

#ifdef __NR_getcpu // 1
  syscallName[__NR_getcpu] = "getcpu";
#endif

#ifdef __NR_process_vm_readv // 1
  syscallName[__NR_process_vm_readv] = "process_vm_readv";
#endif

#ifdef __NR_process_vm_writev // 1
  syscallName[__NR_process_vm_writev] = "process_vm_writev";
#endif

#ifdef __NR_kcmp  // 3
  syscallName[__NR_kcmp] = "kcmp";
#endif

#ifdef __NR_finit_module // 3
  syscallName[__NR_finit_module] = "finit_module";
#endif

#ifdef __NR_sched_setattr // 1
  syscallName[__NR_sched_setattr] = "sched_setattr";
#endif

#ifdef __NR_sched_getattr // 1
  syscallName[__NR_sched_getattr] = "sched_getattr";
#endif

#ifdef __NR_renameat2 // 3
  syscallName[__NR_renameat2] = "renameat2";
#endif

#ifdef __NR_seccomp // 3
  syscallName[__NR_seccomp] = "seccomp";
#endif

#ifdef __NR_getrandom // 1
  syscallName[__NR_getrandom] = "getrandom";
#endif

#ifdef __NR_memfd_create // 1
  syscallName[__NR_memfd_create] = "memfd_create";
#endif

#ifdef __NR_kexec_file_load // 3
  syscallName[__NR_kexec_file_load] = "kexec_file_load";
#endif

#ifdef __NR_bpf // 3
  syscallName[__NR_bpf] = "bpf";
#endif

#ifdef __NR_userfaultfd // 1
  syscallName[__NR_userfaultfd] = "userfaultfd";
#endif

#ifdef __NR_membarrier // 1
  syscallName[__NR_membarrier] = "membarrier";
#endif

#ifdef __NR_mlock2 // 1
  syscallName[__NR_mlock2] = "mlock2";
#endif

#ifdef __NR_copy_file_range // 1
  syscallName[__NR_copy_file_range] = "copy_file_range";
#endif

#ifdef __NR_pkey_mprotect // 1
  syscallName[__NR_pkey_mprotect] = "pkey_mprotect";
#endif

#ifdef __NR_pkey_alloc // 1
  syscallName[__NR_pkey_alloc] = "pkey_alloc";
#endif

#ifdef __NR_pkey_free // 1
  syscallName[__NR_pkey_free] = "pkey_free";
#endif
