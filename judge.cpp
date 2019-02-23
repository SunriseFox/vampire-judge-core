#define ORIG_EAX 11
#define STD256 		256 	//status return adder;

#define MS2S	1000	//From ms to s (time transfe)
#define PAGESIZE   4	//Size of one page in memory(KB)

#define OUTPUT_FILE_SIZE	2500000
#define	LANGUAGE_C	0
#define LANGUAGE_CPP	1
#define LANGUAGE_FPC	2
#define LANGUAGE_JAVA	3
#define LANGUAGE_GPP	4


#define LANG_C "c"
#define LANG_CPP "cpp"
#define LANG_JAVA "java"

#define RU	100	//Running
#define	CE	101	//Compile Error
#define CI	120	//Compiling status
#define WA	102	//Wrong Answer
#define RE	103	//Runtime Error
#define ML	104	//Memory Limit Exceed
#define TL	105	//Time Limit Exceed
#define OL	106	//Output Limit Exceed
#define AC	107	//Accept
#define PE	108	//Presentation Error
#define FL	109	//Function Limit Exceed
#define DM	110	//Detailed Mode
#define SW	118	//System Error

#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <csignal>

#include <string>
#include <map>

#include <fcntl.h>
#include <asm/unistd.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

using namespace std;

#define NOT_ALLOWED 1
#define ALLOWED 2

#define F_NO ret=NOT_ALLOWED
#define F_YES ret=ALLOWED

#define abs(x) (((x)>=0)?(x):-(x))

static map<string, string> param;
static map<string, string> path;

static unsigned time_limit = 0;
static unsigned mem_limit = 0;
static unsigned cases = 0;
static int is_spj = 0;
static int is_nkpc = 0;
static pid_t pid;
static int  nSensitiveCall = 0;

static unsigned real_mem, real_time;

const int SYSTEM_TIME_GAS = 0;
const int SYSTEM_BASE_MEM = 75;

long getpidmem(pid_t pid);
void finish(int status);
int flimit(long orig_eax);
int mytime();
void re_time();

int compare(string exec_in, string exec_out, string std_out);
int spj(string exec_in, string exec_out,string std_out);
int dotest(unsigned which_case);

long getpidmem(pid_t pid)
{
    FILE *fd;
    int m;
    string memfile = string("/proc/")+ to_string(pid) + string("/statm");
    if ((fd = fopen(memfile.c_str (), "r")) != nullptr){
        fscanf(fd,"%d",&m);
        fclose(fd);
        return m * PAGESIZE;
    }
    return 0;
}

int mytime()
{
    struct timeval tv;
    struct timezone tz;
    gettimeofday (&tv , &tz);
    return (tv.tv_usec);
}

void re_time()
{
    int tmp_time = static_cast<int>(real_time / 10) * 10;
    int tmp_mem = static_cast<int>(real_mem / 32) * 32;
    if (tmp_mem < 32) tmp_mem = 32;
    ofstream oft(path["time"].c_str ());
    oft << tmp_time << endl;
    oft.close ();
    ofstream ofm(path["memory"].c_str ());
    ofm << tmp_mem << endl;
    ofm.close ();
}

int compare(string exec_in, string exec_out, string diff_out)
{
    // string difcmd = string("diff ") + exec_in + " " + exec_out + " >" + diff_out;

    // int status = system(difcmd.c_str());

    // if (status == 0 * STD256)
    //     return AC;

    string difcmd = string("diff --ignore-space-change --ignore-all-space --ignore-blank-lines --ignore-case --brief ") + exec_in + " " + exec_out + " >" + diff_out;
    int status = system(difcmd.c_str());

    if (status == 0 * STD256)
        // return PE;
        return AC;
    return WA;
}

int spj(string exec_in, string exec_out, string std_out)
{
    string spjcmd = path["spj"] + " " + exec_in + " " + exec_out + " " + std_out + " >/dev/null";

    cout << "spjfile "<<spjcmd << endl;
    int status = system(spjcmd.c_str ());
    cout << "special judge returned: " << status << endl;
    if(WIFEXITED(status)){
      switch  (WEXITSTATUS(status)) {
        case 0: return WA;
        case 1: return AC;
        case 2: return PE;
        default: return WEXITSTATUS(status);
      }
    }
    cout << "special judge program is killed by system..." << endl;
    return SW;
}

int dotest(unsigned which_case)
{
    cout << "begin test for case " << which_case << endl;

    int case_result = 0 ;
    map<string, string> extra;
    extra["stdin"] = path["stdin"] + "/" + to_string(which_case) + ".in";
    extra["stdout"] = path["stdout"] + "/" + to_string(which_case) + ".out";
    extra["execout"] = path["execout"] + "/" + to_string(which_case) + ".out";
    extra["diff"] = path["diff"] + "/" + to_string(which_case) + ".diff";

    real_time =0;
    real_mem = 0;

    if ((pid = fork())<0) {
        cout << "fork for judge process failed..." << endl;
        finish(SW);
    }

    if (pid == 0)
    {
        /* Most kinds of resource restrictions are applied through the *setrlimit*
        550      * system call, with the exceptions of virtual memory limit and the cpu
        551      * usage limit.
        552      * Because we might have already changed identity by this time, the hard
        553      * limits should remain as they were. Thus we must invoke a *getrlimit*
        554      * ahead of time to load original hard limit value.
        555      * Also note that, cpu usage limit should be set LAST to reduce overhead. */
        /* Virtual memory usage can be inspected by the corresponding fields in
        584      * /proc/#/stat, but if procfs is missing, we will have to depend on the
        585      * setrlimit() system call to impose virtual memory quota limit.
        586      * However, this may result in an unplesant side-effect that some of the
        587      * stack overrun will be reported as SIGSEGV.*/
        rlimit rlimits;

        if (getrlimit(RLIMIT_CPU, &rlimits) < 0) {
            cout << "get cpu limit failed..." << endl;
            finish (SW);
        }

        rlimits.rlim_cur = time_limit / MS2S + 1;
        rlimits.rlim_max = min(time_limit / MS2S * 2, time_limit / MS2S + 4);
        setrlimit(RLIMIT_CPU, &rlimits);

        if (getrlimit(RLIMIT_AS, &rlimits) < 0) {
            cout << "get memory limit failed..." << endl;
            finish (SW);
        }
        rlimits.rlim_cur = mem_limit * 1024 * 2;
        rlimits.rlim_max = mem_limit * 1024 * 2 * 2;
        setrlimit(RLIMIT_AS, &rlimits);

        if (getrlimit(RLIMIT_FSIZE, &rlimits) < 0) {
            cout << "get output size limit failed..." << endl;
            finish (SW);
        }

        rlimits.rlim_cur = OUTPUT_FILE_SIZE;
        rlimits.rlim_max = OUTPUT_FILE_SIZE * 2;
        setrlimit(RLIMIT_FSIZE, &rlimits);

        cout << "execution begin" << endl;

        FILE *file_in = freopen(extra["stdin"].c_str(), "r", stdin);
        FILE *file_out = freopen(extra["execout"].c_str(), "w", stdout);

        if (file_in == nullptr || file_out == nullptr) {
            fclose(file_in);
            fclose(file_out);
            cout << "failed to redirect input & output..." << endl;
            finish(SW);
        }

        setuid(99);
        setgid(99);
        nice(10);

        // TODO...
//        if ( language == LANGUAGE_JAVA ) { //JAVA使用内置的安全管理器，而不能使用ptrace，因为java本身肯定需要进行系统掉用
//            sprintf(exec_cmd, "%s%s/", PATH_EXEC, solution_id);
//            sprintf(temp, "1>%s", exec_out);
//            ptrace(PTRACE_TRACEME, 0, (char *)1, 0);
//            execl("/usr/bin/java", "java", "-Djava.security.manager", "-client", "-Xms2m", "-Xmx256m", "-cp", exec_cmd, "Main", temp, " 2>&1", NULL);
//        }

        ptrace(PTRACE_TRACEME, 0, (void*)(0x1), 0);
        execlp(path["exec"].c_str(), path["exec"].c_str(), nullptr);

        fclose(file_in);
        fclose(file_out);

        cout << "execution failed" << endl;

    } else if (pid > 0) {

        nSensitiveCall=0;

        int waitre, status;
        long orig_eax, rec_time = mytime ();
        unsigned check_mem = 0;
        unsigned check_max_mem = 0;
        rusage usage;

        while (pid == wait4(pid, &status, 0, &usage)){
            if (WIFSIGNALED(status)){
                check_mem = getpidmem(pid);
                ptrace(PTRACE_KILL, pid, reinterpret_cast<char*>(1), 0);
                cout << "user program terminated by system signal..." << WTERMSIG(status) << endl;
                status = WTERMSIG(status);
                break;
            }

            if (WIFEXITED(status)){
                ptrace(PTRACE_KILL, pid, reinterpret_cast<char*>(1), 0);
                cout << "user program exited normally..." << endl;
                cout << "time: " << mytime()-rec_time << endl;
                cout << "status: " << WEXITSTATUS(status) << endl;
                status = WEXITSTATUS(status);
                break;
            }
            if (WIFSTOPPED(status)){
                if (WSTOPSIG(status) == SIGTRAP) {
                    orig_eax = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL);
                    if (orig_eax != 0 && param["lang"] != LANG_JAVA){
                        switch (flimit(orig_eax))
                        {
                        case ALLOWED:
                            break;
                        case NOT_ALLOWED:
                            cout << "got illegal syscall: " << orig_eax << endl;
                            ptrace(PTRACE_KILL, pid, reinterpret_cast<char*>(1), 0);
                            return (status = FL);
                            break;
                        case 0:
                        default:
                            cout << "got undefined syscall: " << orig_eax << endl;
                            break;
                        }
                    }

                    if (orig_eax != __NR_read && orig_eax != __NR_write){  		//避免读写陷入死循环后，调用太多，导致性能降低
                        check_mem = getpidmem(pid);
                        if (check_mem > check_max_mem)
                            check_max_mem = check_mem;
                        if (check_mem > mem_limit)	{
                            cout << "memory limit exceed..." << "limit is: " << mem_limit << ", max: " << check_max_mem << endl;
                            ptrace(PTRACE_KILL, pid, reinterpret_cast<char*>(1), 0);
                            status = ML;
                            break;
                        }
                    }

                    if ((waitre = ptrace(PTRACE_SYSCALL, pid, reinterpret_cast<char*>(1), 0)) == -1){
                        cout << "failed to continue from breakpoint..." << endl;
                        finish (SW);
                    }
                }
                else {
                    status = WSTOPSIG(status);
                    ptrace(PTRACE_KILL, pid, (char *)1, 0);
                    cout << "program terminated with code " << status << "..." << endl;
                    break;
                }
            }
        }

        real_time = usage.ru_utime.tv_sec * 1000 + usage.ru_stime.tv_sec * 1000 + (usage.ru_stime.tv_usec + usage.ru_utime.tv_usec) / 1000;

        cout << "time: " << real_time << endl;
        real_mem = usage.ru_minflt * 4;
        cout << "memory: " << check_max_mem << endl;

//        cout << "debug info: " << endl;
//        cout << "usage.ru_maxrss: " << usage.ru_maxrss << endl;     /* maximum resident set size */
//        cout << "usage.ru_ixrss: " << usage.ru_ixrss << endl;       /* integral shared memory size */
//        cout << "usage.ru_idrss: " << usage.ru_idrss << endl;       /* integral unshared data size */
//        cout << "usage.ru_isrss: " << usage.ru_isrss << endl;       /* integral unshared stack size */
//        cout << "usage.ru_minflt: " << usage.ru_minflt << endl;     /* page reclaims */
//        cout << "usage.ru_majflt: " << usage.ru_majflt << endl;     /* page faults */
//        cout << "usage.ru_nswap: " << usage.ru_nswap << endl;       /* swaps */
//        cout << "usage.ru_inblock: " << usage.ru_inblock << endl;   /* block input operations */
//        cout << "usage.ru_oublock: " << usage.ru_oublock << endl;   /* block output operations */
//        cout << "usage.ru_msgsnd: " << usage.ru_msgsnd << endl;     /* messages sent */
//        cout << "usage.ru_msgrcv: " << usage.ru_msgrcv << endl;     /* messages received */
//        cout << "usage.ru_nsignals: " << usage.ru_nsignals << endl; /* signals received */
//        cout << "usage.ru_nvcsw: " << usage.ru_nvcsw << endl;       /* voluntary context switches */
//        cout << "usage.ru_nivcsw: " << usage.ru_nivcsw << endl;     /* involuntary " */

        switch (status)
        {
        case 0      : case_result = 0; break;
        case SIGXCPU: case_result = TL; break;
        case SIGXFSZ: case_result = OL; break;
        case SIGSEGV: case_result = RE; break;
        case SIGABRT: case_result = ML; break;
        case SIGFPE : case_result = RE; break;
        case SIGBUS	: case_result = RE; break;
        case SIGILL	: case_result = RE; break;
        case SIGKILL: case_result = ML; break;
        default     : case_result = RE; break;
        }

        if (real_time > time_limit) {
          case_result = TL;
        }else if (real_mem > mem_limit || check_max_mem > mem_limit ) {
            case_result = ML;
        }else if (real_mem <= mem_limit ) {
            real_mem=check_max_mem;
        }

        re_time();


        if (case_result == 0)
        {
            if (is_spj == 1)
                case_result = spj(extra["stdin"], extra["execout"], extra["stdout"]);
            else
                case_result = compare(extra["stdout"], extra["execout"], extra["diff"]);
        }
        ofstream of(path["detail"], ios_base::app | ios_base::out);
        of << "case " << which_case << ": " << (case_result == RE ? status : case_result) << endl;
        of.close ();
        cout << "case " << which_case << " finished with " << case_result << endl;
        return case_result;
    }
    return SW;
}

void create_folder(string path) {
    const int error = system((string("mkdir -p ") + path).c_str ());
    if (error != 0)
    {
        cout << "Create directory at " << path << " failed..." << endl;
        exit(error);
    }
}

void finish(int status)
{
    re_time();
    ofstream of(path["result"].c_str ());
    of << status << endl;
    cout << "end" << endl;
    kill(0, SIGKILL);
    exit(status);
}

int main(){

    cout << "start" << endl;
    {
        string str[9];
        for(int i = 0; i < 9; i++)
            getline(cin, str[i]);

        param["system"] = str[0];
        param["sid"] = str[1];
        param["pid"] = str[2];
        param["lang"] = str[3];
        time_limit = stoul(str[4]);
        mem_limit = stoul(str[5]);
        cases = stoul(str[6]);
        is_spj = stoi(str[7]);
        is_nkpc = stoi(str[8]);
    }

    // Directory

    path["solution"] = param["system"] + "/solutions/" + param["sid"];
    create_folder(path["solution"]);

    path["temp"] = path["solution"] + "/temp";
    system((string("rm ")+path["temp"] + string(" -rf")).c_str ());
    create_folder(path["temp"]);

    path["execout"] = path["solution"] + "/execout";
    create_folder(path["execout"]);

    path["stdin"] = param["system"] + "/problem_data/" + param["pid"];
    path["stdout"] = param["system"] + "/problem_data/" + param["pid"];

    path["diff"] = path["temp"];

    // Files
    path["result"] = path["temp"] + "/result";
    path["time"] = path["temp"] + "/time";
    path["memory"] = path["temp"] + "/memory";
    path["detail"] = path["temp"] + "/detail";

    path["code"] = path["solution"] + "/main." + param["lang"];
    path["exec"] = path["temp"] + "/main";
    path["spj"] = param["system"] + "/problem_spj/" + param["pid"];


    path["cmpinfo"] = path["solution"] + "/main.cmpinfo";
    unlink (path["cmpinfo"].c_str ());


    // TODO...
    if ( param["lang"] == LANG_JAVA ) {
        time_limit *= 5;
        mem_limit = 512000; // TODO: cannot limit java memory
    }

    // Compile
    string compile_command;

    if(param["lang"] == LANG_C) {
        compile_command = "gcc -DONLINE_JUDGE -O2 -ansi -fno-asm -Wall -o "
                + path["exec"] + " -lm -static " + path["code"] + " >>"
                + path["cmpinfo"] + " 2>&1";
    } else if(param["lang"] == LANG_CPP) {
        compile_command = "g++ -Wall -Wextra -DONLINE_JUDGE -O2 -std=c++14 -o "
                + path["exec"] + " -lm -static " + path["code"] + " >>"
                + path["cmpinfo"] + " 2>&1";
    } else {
        cout << "language is not supported..." << endl;
        exit(SW);
    }

    pid_t pid = fork();
    if(pid == -1) {
        cout << "fork complier process failed..." << endl;
        exit(pid);
    }
    if(pid == 0) {
        alarm(10);
        signal(SIGALRM, [](int sig){exit(-1);});
        int ret = system(compile_command.c_str ());
        unsigned int sec = 10 - alarm(0);
        cout << "compile time is " << sec << " seconds" << endl;
        if(WIFEXITED(ret))
            exit(WEXITSTATUS(ret));
        raise(WTERMSIG(ret));
    } else {
        int status;
        wait(&status);
        if(!WIFEXITED(status)) {
            cout << "compiler process exited unexpectedly... " << WTERMSIG(status) << endl;
            return WTERMSIG(status);
        }
        status = WEXITSTATUS(status);
        cout << "compiler return code is : " << status << endl;
        if(status != 0) {
            finish (CE);
        }
    }

    //compile special judge (online support for c++)
    if(is_spj == 1){
        string spj_compile_command = "g++ -std=c++11 " + path["spj"] + ".cpp -o " + path["spj"];
        cout<< "spj compile command:" << spj_compile_command << endl;
        pid = fork();
        if(pid == 0) {
            alarm(10);
            signal(SIGALRM, [](int sig){exit(-1);});
            int ret = system(spj_compile_command.c_str ());
            unsigned int sec = 10 - alarm(0);
            cout << "spj compile time is " << sec << " seconds" << endl;
            if(WIFEXITED(ret))
                exit(WEXITSTATUS(ret));
            raise(WTERMSIG(ret));
        } else {
            int status;
            wait(&status);
            if(!WIFEXITED(status)) {
                cout << "spj compiler process exited unexpectedly... " << WTERMSIG(status) << endl;
                return WTERMSIG(status);
            }
            status = WEXITSTATUS(status);
            cout << "spj compiler return code is : " << status << endl;
            if(status != 0) {
                finish (CE);
            }
        }
    }

    cout << "judge" << endl;
    cout << "solution_id: " << param["sid"] << endl;


    unsigned case_AC = 0;
    unsigned case_PE = 0;

    int result = SW;

    if (cases == 0)          //单测试数据
    {
        result = dotest(1);
        finish (result);
    } else if (cases > 0 && is_nkpc == 0) {
        unsigned total_time = 0;
        for (unsigned i = 1; i <= cases; i++)
        {
            result = dotest (i);

            total_time += real_time;
            cout << "total time is: " << total_time << endl;

            real_time = total_time;
            if (total_time > time_limit + SYSTEM_TIME_GAS){
                re_time();
                finish (TL);
            }
            if (result == AC) case_AC++;
            else if (result == PE) case_PE++;
            else finish (result);
        }

        real_time = total_time;
        re_time();

        if (cases == case_AC)
            finish (AC);
        else if (cases == case_PE)
            finish (PE);
        finish (WA);
    } else  if (cases > 0 && is_nkpc == 1) {
        result = SW;
        unsigned total_time = 0;
        unlink (path["result"].c_str ());
        for (unsigned i = 1; i <= cases; i++)
        {
            result = dotest(i);
            total_time += real_time;
            real_time = total_time;

            if (result == AC) case_AC++;

            cout << "total time is: " << total_time << endl;
        }

        re_time();

        if (cases == case_AC)
            finish (AC);
        finish (DM);
        return 0;
    }
    cout << "should not return from main..." << endl;
    finish (SW);
    return -1;
}


int flimit(long orig_eax)
{
    int ret=0;
    switch (orig_eax)
    {
    case __NR_exit: F_YES ;  break;//  1中止进程
    case __NR_fork: F_NO ;   break;//  2创建一个新进程
    case __NR_read: F_YES ;  break;//  3read读文件
    case __NR_write:F_YES ;   break;//  4write写文件
    case __NR_open: F_NO ;  break;//  5open打开文件
    case __NR_close: F_NO ;  break;//  6close关闭文件描述字
    case __NR_waitpid: F_NO ;  break;//  7等待子进程终止
    case __NR_creat: F_NO ;  break;//  8creat创建新文件
    case __NR_link: F_NO ;  break;//  9创建链接
    case __NR_unlink: F_NO ;  break;// 10删除链接
    case __NR_execve:nSensitiveCall++; if (nSensitiveCall>2) F_NO ; F_YES; break;// 11运行可执行文件
    case __NR_chdir: F_NO ;  break;// 12改变当前工作目录
    case __NR_time: F_NO ;  break;// 13取得系统时间
    case __NR_mknod: F_NO ;  break;// 14创建索引节点
    case __NR_chmod: F_NO ;  break;// 15改变文件方式
    case __NR_lchown:F_NO ;   break;// 16改变文件的属主或用户组
    case __NR_break:   break;// 17
    case __NR_oldstat:   break;// 18取文件状态信息
    case __NR_lseek:   break;// 19移动文件指针
    case __NR_getpid:F_NO;   break;// 20获取进程标识号
    case __NR_mount: F_NO ;  break;// 21安装文件系统
    case __NR_umount: F_NO ;  break;// 22卸下文件系统
    case __NR_setuid: F_NO ;  break;// 23设置用户标志号
    case __NR_getuid: F_YES ;  break;// 24获取用户标识号
    case __NR_stime: F_NO ;  break;// 25设置系统日期和时间
    case __NR_ptrace:F_NO ;   break;// 26进程跟踪
    case __NR_alarm: F_NO ;  break;// 27设置进程的闹钟
    case __NR_oldfstat:   break;// 28取文件状态信息
    case __NR_pause: F_NO ;  break;// 29挂起进程，等待信号
    case __NR_utime: F_NO ;  break;// 30改变文件的访问修改时间
    case __NR_stty: F_NO ;  break;// 31
    case __NR_gtty: F_NO ;  break;// 32
    case __NR_access:   break;// 33确定文件的可存取性
    case __NR_nice: F_NO ;  break;// 34改变分时进程的优先级
    case __NR_ftime: F_NO ;  break;// 35
    case __NR_sync:   break;// 36将内存缓冲区数据写回硬盘
    case __NR_kill: F_NO ;  break;// 37向进程或进程组发信号
    case __NR_rename: F_NO ;  break;// 38文件改名
    case __NR_mkdir: F_NO ;  break;// 39创建目录
    case __NR_rmdir: F_NO ;  break;// 40删除目录
    case __NR_dup:   break;// 41复制已打开的文件描述字
    case __NR_pipe: F_NO ;  break;// 42创建管道
    case __NR_times: F_NO ;  break;// 43取进程运行时间
    case __NR_prof:   break;// 44
    case __NR_brk: F_YES ;  break;// 45 改变数据段空间的分配
    case __NR_setgid: F_NO ;  break;// 46设置组标志号
    case __NR_getgid:  F_YES ; break;// 47获取组标识号
    case __NR_signal: F_NO ;  break;// 48 信号
    case __NR_geteuid: F_YES ;  break;// 49获取有效用户标识号
    case __NR_getegid: F_YES ;  break;// 50获取有效组标识号
    case __NR_acct: F_NO ;  break;// 51启用或禁止进程记账
    case __NR_umount2: F_NO ;  break;// 52
    case __NR_lock: F_NO ;  break;// 53
    case __NR_ioctl:   break;// 54I/O总控制函数
    case __NR_fcntl:   break;// 55文件控制
    case __NR_mpx:   break;// 56
    case __NR_setpgid: F_NO ;  break;// 57
    case __NR_ulimit:   break;// 58
    case __NR_oldolduname:   break;//59
    case __NR_umask: F_NO ;  break;// 60设置文件权限掩码
    case __NR_chroot: F_NO ;  break;// 61
    case __NR_ustat:   break;// 62取文件系统信息
    case __NR_dup2:   break;// 63按指定条件复制文件描述字
    case __NR_getppid:  F_YES ; break;// 64
    case __NR_getpgrp:  F_YES ; break;// 65
    case __NR_setsid: F_NO ;  break;// 66设置会晤标识号
    case __NR_sigaction:  F_YES ; break;// 67设置对指定信号的处理方法
    case __NR_sgetmask:   break;// 68取得现有阻塞信号掩码,已被sigprocmask代替
    case __NR_ssetmask:   break;// 69ANSI C的信号处理函数,作用类似sigaction
    case __NR_setreuid: F_NO ;  break;// 70分别设置真实和有效的用户标识号
    case __NR_setregid: F_NO ;  break;// 71分别设置真实和有效的的组标识号
    case __NR_sigsuspend: F_NO ;  break;// 72挂起进程等待特定信号
    case __NR_sigpending: F_NO ;  break;// 73为指定的被阻塞信号设置队列
    case __NR_sethostname: F_NO ;  break;//74设置主机名称
    case __NR_setrlimit: F_NO ;  break;// 75设置系统资源上限
    case __NR_getrlimit:   break;// 76	/* Back compatible 2Gig limited rlimit */获取系统资源上限
    case __NR_getrusage:   break;// 77获取系统资源使用情况
    case __NR_gettimeofday: F_NO ;  break;// 78取时间和时区
    case __NR_settimeofday: F_NO ;  break;//79设置时间和时区
    case __NR_getgroups: F_YES ;  break;// 80获取后补组标志清单
    case __NR_setgroups: F_NO ;  break;// 81设置后补组标志清单
    case __NR_select: F_NO ;  break;// 82对多路同步I/O进行轮询
    case __NR_symlink: F_NO ;  break;// 83创建符号链接
    case __NR_oldlstat:   break;// 84
    case __NR_readlink:  F_YES ; break;// 85读符号链接的值
    case __NR_uselib: F_NO ;  break;// 86选择要使用的二进制函数库
    case __NR_swapon: F_NO ;  break;// 87打开交换文件和设备
    case __NR_reboot: F_NO ;  break;// 88重新启动
    case __NR_readdir: F_NO ;  break;// 89读取目录项
    case __NR_mmap: F_YES ; break;// 90映射虚拟内存页 __NR_mmap
    case __NR_munmap: F_YES ;  break;// 91去除内存页映射
    case __NR_truncate:   break;// 92截断文件
    case __NR_ftruncate:   break;// 93截断文件
    case __NR_fchmod: F_NO ;  break;// 94改变文件方式
    case __NR_fchown: F_NO ;  break;// 95改变文件的属主或用户组
    case __NR_getpriority:   break;// 96
    case __NR_setpriority: F_NO ;  break;// 97
    case __NR_profil:   break;// 98
    case __NR_statfs:   break;// 99取文件系统信息
    case __NR_fstatfs:   break;//100取文件系统信息
    case __NR_ioperm: F_NO ;  break;//101设置端口I/O权限
    case __NR_socketcall: F_NO ;  break;//102socket系统调用
    case __NR_syslog: F_NO ;  break;//103
    case __NR_setitimer: F_NO ;  break;//104设置计时器值
    case __NR_getitimer: F_NO ;  break;//105获取计时器值
    case __NR_stat:   break;//106取文件状态信息
    case __NR_lstat:   break;//107取文件状态信息
    case __NR_fstat:   break;//108取文件状态信息
    case __NR_olduname:   break;//109
    case __NR_iopl:F_NO ;   break;//110改变进程I/O权限级别
    case __NR_vhangup: F_NO ;  break;//111挂起当前终端
    case __NR_idle: F_NO ;  break;//112
    case __NR_vm86old: F_NO ;  break;//113进入模拟8086模式
    case __NR_wait4: F_NO ;  break;//114等待子进程终止
    case __NR_swapoff: F_NO ;  break;//115关闭交换文件和设备
    case __NR_sysinfo:   break;//116取得系统信息
    case __NR_ipc: F_NO ;  break;//117进程间通信总控制调用
    case __NR_fsync:   break;//118把文件在内存中的部分写回磁盘
    case __NR_sigreturn:   break;//119
    case __NR_clone: F_NO ;  break;//120 按指定条件创建子进程
    case __NR_setdomainname: F_NO ;  break;//121设置域名
    case __NR_uname:	F_YES ;  break;//122 //获取当前UNIX系统的名称、版本和主机等信息
    case __NR_modify_ldt: F_NO ;  break;//123读写进程的本地描述表
    case __NR_adjtimex: F_NO ;  break;//124调整系统时钟
    case __NR_mprotect:   break;//125设置内存映像保护
    case __NR_sigprocmask:   break;//126根据参数对信号集中的信号执行阻塞/解除阻塞等操作
    case __NR_create_module:F_NO ;   break;//127创建可装载的模块项
    case __NR_init_module: F_NO ;  break;//128初始化模块
    case __NR_delete_module: F_NO ;  break;//129删除可装载的模块项
    case __NR_get_kernel_syms: F_NO ;  break;//130取得核心符号,已被query_module代替
    case __NR_quotactl: F_NO ;  break;//131控制磁盘配额
    case __NR_getpgid: F_YES ; break;//132获取指定进程组标识号
    case __NR_fchdir: F_NO ;  break;//133改变当前工作目录
    case __NR_bdflush: F_NO ;  break;//134控制bdflush守护进程
    case __NR_sysfs:   break;//135取核心支持的文件系统类型
    case __NR_personality: F_NO ;  break;//136设置进程运行域
    case __NR_afs_syscall: F_NO ;  break;//137 /* Syscall for Andrew File System */
    case __NR_setfsuid: F_NO ;  break;//138设置文件系统检查时使用的用户标识号
    case __NR_setfsgid: F_NO ;  break;//139设置文件系统检查时使用的组标识号
    case __NR__llseek: F_YES ;  break;//140在64位地址空间里移动文件指针
    case __NR_getdents: F_NO ;  break;//141读取目录项
    case __NR__newselect: F_NO ;  break;//142
    case __NR_flock: F_NO ;  break;//143文件加/解锁
    case __NR_msync:   break;//144将映射内存中的数据写回磁盘
    case __NR_readv:   break;//145从文件读入数据到缓冲数组中
    case __NR_writev:   break;//146将缓冲数组里的数据写入文件
    case __NR_getsid:   break;//147获取会晤标识号
    case __NR_fdatasync:   break;//148
    case __NR__sysctl: F_NO ;  break;//149读/写系统参数
    case __NR_mlock: F_NO ;  break;//150内存页面加锁
    case __NR_munlock: F_NO ;  break;//151内存页面解锁
    case __NR_mlockall: F_NO ;  break;//152调用进程所有内存页面加锁
    case __NR_munlockall: F_NO ;  break;//153调用进程所有内存页面解锁
    case __NR_sched_setparam: F_NO ;  break;//154设置进程的调度参数
    case __NR_sched_getparam:   break;//155取得进程的调度参数
    case __NR_sched_setscheduler: F_NO ;  break;//156取得指定进程的调度策略
    case __NR_sched_getscheduler:   break;//157设置指定进程的调度策略和参数
    case __NR_sched_yield: F_NO ;  break;//158进程主动让出处理器,并将自己等候调度队列队尾
    case __NR_sched_get_priority_max:   break;//159取得静态优先级的上限
    case __NR_sched_get_priority_min:   break;//160取得静态优先级的下限
    case __NR_sched_rr_get_interval:   break;//161取得按RR算法调度的实时进程的时间片长度
    case __NR_nanosleep: F_NO ;  break;//162使进程睡眠指定的时间
    case __NR_mremap:   break;//163重新映射虚拟内存地址
    case __NR_setresuid: F_NO ;  break;//164分别设置真实的,有效的和保存过的用户标识号
    case __NR_getresuid:   break;//165分别获取真实的,有效的和保存过的用户标识号
    case __NR_vm86: F_NO ;  break;//166进入模拟8086模式
    case __NR_query_module: F_NO ;  break;//167查询模块信息
    case __NR_poll: F_NO ;  break;//168I/O多路转换
    case __NR_nfsservctl:F_NO ;   break;//169对NFS守护进程进行控制
    case __NR_setresgid: F_NO ;  break;//170分别设置真实的,有效的和保存过的组标识号
    case __NR_getresgid:   break;//171分别获取真实的,有效的和保存过的组标识号
    case __NR_prctl : F_NO ;  break;//172对进程进行特定操作
    case __NR_rt_sigreturn:   break;//173
    case __NR_rt_sigaction:   break;//174设置对指定信号的处理方法
    case __NR_rt_sigprocmask:   break;//175根据参数对信号集中的信号执行阻塞/解除阻塞等操作
    case __NR_rt_sigpending:   break;//176为指定的被阻塞信号设置队列
    case __NR_rt_sigtimedwait:   break;//177
    case __NR_rt_sigqueueinfo:   break;//178
    case __NR_rt_sigsuspend:   break;//179挂起进程等待特定信号
    case 180:   break;//180 //__NR_pread64 __NR_pread对文件随机读
    case 181:   break;//181//__NR_pwrite64 __NR_pwrite(redhat9)对文件随机写
    case __NR_chown: F_NO ;  break;//182
    case __NR_getcwd:   break;//183
    case __NR_capget:   break;//184获取进程权限
    case __NR_capset: F_NO ;  break;//185 设置进程权限
    case __NR_sigaltstack:   break;//186
    case __NR_sendfile: F_NO ;  break;//187在文件或端口间传输数据
    case __NR_getpmsg: F_NO ;  break;//188	/* some people actually want streams */
    case __NR_putpmsg: F_NO ;  break;//189	/* some people actually want streams */
    case __NR_vfork: F_NO ;  break;//190创建一个子进程，以供执行新程序，常与execve等同时使用
    case __NR_ugetrlimit:   break;//191	/* SuS compliant getrlimit */
    case __NR_mmap2:  F_YES; break;//192映射虚拟内存页
    case __NR_truncate64:   break;//193截断文件
    case __NR_ftruncate64:   break;//194截断文件
    case __NR_stat64:   break;//195
    case __NR_lstat64:   break;//196
    case __NR_fstat64: F_YES ;  break;//197
    case __NR_lchown32:   break;//198改变文件的属主或用户组
    case __NR_getuid32: F_YES ;  break;//199获取用户标识号
    case __NR_getgid32: F_YES ;  break;//200获取组标识号
    case __NR_geteuid32:F_YES ;   break;//201获取有效用户标识号
    case __NR_getegid32: F_YES ;  break;//202获取有效组标识号
    case __NR_setreuid32: F_NO ;  break;//203分别设置真实和有效的用户标识号
    case __NR_setregid32: F_NO ;  break;//204分别设置真实和有效的的组标识号
    case __NR_getgroups32:F_YES ;   break;//205获取后补组标志清单
    case __NR_setgroups32: F_NO ;  break;//206设置后补组标志清单
    case __NR_fchown32: F_NO ;  break;//207改变文件的属主或用户组
    case __NR_setresuid32: F_NO ;  break;//208分别设置真实和有效的用户标识号
    case __NR_getresuid32: F_YES ;  break;//209分别获取真实的,有效的和保存过的用户标识号
    case __NR_setresgid32: F_NO ;  break;//210分别设置真实的,有效的和保存过的组标识号
    case __NR_getresgid32:F_YES ;   break;//211分别获取真实的,有效的和保存过的组标识号
    case __NR_chown32: F_NO ;  break;//212改变文件的属主或用户组
    case __NR_setuid32: F_NO ;  break;//213设置用户标志号
    case __NR_setgid32: F_NO ;  break;//214设置组标志号
    case __NR_setfsuid32: F_NO ;  break;//215设置文件系统检查时使用的用户标识号
    case __NR_setfsgid32: F_NO ;  break;//216设置文件系统检查时使用的组标识号
    case __NR_pivot_root:   break;//217
    case __NR_mincore: F_NO ;  break;//218
    case __NR_madvise:   break;//219
        //case __NR_madvise1:   break;//219	/* delete when C lib stub is removed */
    case __NR_getdents64: F_YES ;   break;//220
    case __NR_fcntl64: F_YES ;   break;//221文件控制
    case 223:   break;//223	For RH9 __NR_security/* syscall for security modules */ //For EL5 /* 223 is unused */
    case __NR_gettid:   break;//224
    case __NR_readahead:   break;//225
    case __NR_setxattr: F_NO ;  break;//226
    case __NR_lsetxattr:   break;//227
    case __NR_fsetxattr:   break;//228
    case __NR_getxattr:   break;//229
    case __NR_lgetxattr:   break;//230
    case __NR_fgetxattr:   break;//231
    case __NR_listxattr:   break;//232
    case __NR_llistxattr:   break;//233
    case __NR_flistxattr:   break;//234
    case __NR_removexattr:   break;//235
    case __NR_lremovexattr:   break;//236
    case __NR_fremovexattr:   break;//237
    case __NR_tkill: F_NO ;  break;//238向进程或进程组发信号
    case __NR_sendfile64: F_NO ;  break;//239在文件或端口间传输数据
    case __NR_futex: F_NO ; break;//240
    case __NR_sched_setaffinity: F_NO ;  break;//241
    case __NR_sched_getaffinity:   break;//242
    case __NR_set_thread_area: break;//243
    case __NR_get_thread_area:   break;//244
        /* case __NR_io_setup	245 */
        /* case __NR_io_destroy	246 */
        /* case __NR_io_getevents	247 */
        /* case __NR_io_submit	248 */
        /* case __NR_io_cancel	249 */
        /* case __NR_alloc_hugepages	250 */
        /* case __NR_free_hugepages	251 */
    case __NR_exit_group: F_YES ;  break;//252
        /* case __NR_lookup_dcookie	253 */
        /* case __NR_sys_epoll_create 254 */
        /* case __NR_sys_epoll_ctl	255 */
        /* case __NR_sys_epoll_wait	256 */
        /* case __NR_remap_file_pages 257 */
    case __NR_set_tid_address: F_NO ;  break;//258

    default:
        break;
    }
    return ret;

}

// #define	SIGHUP		1	/* Hangup (POSIX).  */
// #define	SIGINT		2	/* Interrupt (ANSI).  */
// #define	SIGQUIT		3	/* Quit (POSIX).  */
// #define	SIGILL		4	/* Illegal instruction (ANSI).  */
// #define	SIGTRAP		5	/* Trace trap (POSIX).  */
// #define	SIGABRT		6	/* Abort (ANSI).  */
// #define	SIGIOT		6	/* IOT trap (4.2 BSD).  */
// #define	SIGBUS		7	/* BUS error (4.2 BSD).  */
// #define	SIGFPE		8	/* Floating-point exception (ANSI).  */
// #define	SIGKILL		9	/* Kill, unblockable (POSIX).  */
// #define	SIGUSR1		10	/* User-defined signal 1 (POSIX).  */
// #define	SIGSEGV		11	/* Segmentation violation (ANSI).  */
// #define	SIGUSR2		12	/* User-defined signal 2 (POSIX).  */
// #define	SIGPIPE		13	/* Broken pipe (POSIX).  */
// #define	SIGALRM		14	/* Alarm clock (POSIX).  */
// #define	SIGTERM		15	/* Termination (ANSI).  */
// #define	SIGSTKFLT	16	/* Stack fault.  */
// #define	SIGCLD		SIGCHLD	/* Same as SIGCHLD (System V).  */
// #define	SIGCHLD		17	/* Child status has changed (POSIX).  */
// #define	SIGCONT		18	/* Continue (POSIX).  */
// #define	SIGSTOP		19	/* Stop, unblockable (POSIX).  */
// #define	SIGTSTP		20	/* Keyboard stop (POSIX).  */
// #define	SIGTTIN		21	/* Background read from tty (POSIX).  */
// #define	SIGTTOU		22	/* Background write to tty (POSIX).  */
// #define	SIGURG		23	/* Urgent condition on socket (4.2 BSD).  */
// #define	SIGXCPU		24	/* CPU limit exceeded (4.2 BSD).  */
// #define	SIGXFSZ		25	/* File size limit exceeded (4.2 BSD).  */
// #define	SIGVTALRM	26	/* Virtual alarm clock (4.2 BSD).  */
// #define	SIGPROF		27	/* Profiling alarm clock (4.2 BSD).  */
// #define	SIGWINCH	28	/* Window size change (4.3 BSD, Sun).  */
// #define	SIGPOLL		SIGIO	/* Pollable event occurred (System V).  */
// #define	SIGIO		29	/* I/O now possible (4.2 BSD).  */
// #define	SIGPWR		30	/* Power failure restart (System V).  */
// #define SIGSYS		31	/* Bad system call.  */
