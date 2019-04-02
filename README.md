## Vampire Judge Core

### Prerequisite

+ Docker (如果是 Windows 下的 Docker，必须选择 Hyper-V + Linux Container)

### Known Issues in Windows

+ 如果卷 /mnt/data 挂载在 Windows 目录下，Docker 无法进行文件权限控制，可能导致错误的用户程序有权读取该目录的任意文件
+ 如果卷 /mnt/data 挂载在 Windows 目录下，可能存在文件描述符泄露

### Known Issues in KVM / OpenVZ

+ OpenVZ 架构虚拟化无法运行这一内核
+ 不是所有的 KVM 都可以运行，必须显式说明 支持 Docker 或嵌套虚拟化的 KVM 才可以执行

### Build

+ (Linux) 打开 build.sh，修改 `MOUNTFOLDER` 为本地一个已存在的目录
+ (Windows) 打开 build.bat，修改 `MOUNTFOLDER` 为本地一个已存在的目录
+ 运行对应的 `build.sh` 或 `build.bat`

### 测试

+ 项目在 testcase 中提供了测试样例，只需要运行当前目录的 `./test.sh` 或 `test.bat` 即可。

### Usage

+ 执行 `docker exec judgecore ./judgecore <配置文件.json>`（从文件读取配置） 或 `docker exec -ti judgecore ./judgecore stdin` （从 stdin 读取配置）即可。支持多个 json 与 stdin 自动合并。
+ 执行 `docker exec judgecore ./compiler <配置文件.json>` 编译 special judge 程序。

### Configuration File

+ 一个完整的可接受的配置文件（例子在 ./judgecore/conf/）
+ 输出的结果在 <output> 的 result.json

```json5

{
  "debug": true, // [false]
  "sid": 10001, // [undefined]
  "filename": "main.cpp", // [undefined]
  "lang": "c++", // <必填>，可以是 c, c++, javascript, python, go, pypy3
  "pid": 1001, // [undefined]
  "max_time": 1000, // [1000]
  "max_real_time": 2000, // [max_time + 1]
  "max_time_total": 30000, // [30000]
  "max_memory": 65530, // [65530]
  "max_output": 10000000,  // [10000000]
  "max_core": 4, // [4] 注意: 多核心 go 默认使用 4 核心
  "on_error_continue": ["accepted", "presentation error", "wrong answer"], // [["accepted", "presentation error"]]，也可以是 true 或 false
  "test_case_count": 1, // <必填>
  "spj_mode": "compare", // [no]，可以是 no, compare 或 interactive
  "path": {
    "base": null, // [/mnt/data]
    "code": null, // [<base>/code/<pid>/<sid>/<filename>]，如无 pid 和 sid 和 filename 则必填
    "log": null, // [<temp>]
    "output": null, // [<base>/result/<pid>/<sid>/]，如无 pid 和 sid 则必填
    "stdin": null, // [<base>/case/<pid>/]，如无 pid 则必填，应包含 1.in - <test_case_count>.in
    "stdout": null, // [<stdin>]，应包含 1.out - <test_case_count>.out
    "temp": null, // [/tmp/]
    "spj": null, // 如果 spj_mode 不是 no，[<base>/judge/<pid>]
  }
}

```

+ 一个完整的编译 spj 的配置文件：
+ 编译的结果在 STDOUT

```json5

{
  "debug": true, // [false]
  "base_path": "/mnt/data/", // [/mnt/data]
  "pid": 1001, // [undefined]
  "lang": "c++", // <必填>，可以是 c, c++, javascript, python, go
  "code": "/mnt/data/judge/1001.cpp", // [<base_path>/judge/<pid>.<ext>]
  "target": "/mnt/data/judge/1001"  // [<base_path>/judge/<pid>]
}

```

+ Special Judge 调用参数：

```
如果是 compare，将在用户程序执行结束后运行，参数为
< = /dev/null
argv[1] = 该组数据的 stdin
argv[2] = 该组数据的 stdout
argv[3] = 用户程序输出的 execout
argv[4] = 如果用户程序写了文件，存放用户程序写入的文件的文件夹
> = <log>

如果是 interactive，将稍早于用户程序运行，参数为
< = 用户程序的 stdout
argv[1] = 该组数据的 stdin
argv[2] = 该组数据的 stdout
argv[3] = 如果为评测提供额外信息，写入到这个文件
argv[4] = 如果用户程序写了文件，存放用户程序写入的文件的文件夹
> = 用户程序的 stdin


返回值 0 = AC, 1 = PE, 2 = WA, 其他 = SW
```

+ 一个可能的内核输出：

```json5
// 正常程序
{
  "compiler": "", // 编译器信息
  "detail": [ // 对每一个测试样例的输出
    {
      "exitcode": 0,
      "memory": 1848,
      "result": "accepted",
      "status": 0, // enum RESULT {AC = 0, PE, WA, CE, RE, ME, TE, OLE, SLE, SW};
      "time": 0,
      "extra": "<特殊评测程序的输出>",
    }
  ],
  "extra": null, // 可能存在的错误详情
  "memory": 1848,
  "result": "accepted",
  "status": 0,
  "time": 0
}
// 数组越界
{
  "compiler": "",
  "detail": [
    {
      "exitcode": 0,
      "memory": 1848,
      "result": "runtime error",
      "signal": 11, // 运行错误特有的字段
      "signal_str": "Segmentation fault", // 运行错误特有的字段
      "status": 4,
      "time": 0,
      "extra": null,
    }
  ],
  "extra": null,
  "memory": 1848,
  "result": "runtime error",
  "status": 4,
  "time": 0
}
// 非法系统调用
{
  "compiler": "",
  "detail": [
    {
      "exitcode": 0,
      "memory": 1756,
      "result": "syscall not allowed",
      "signal": 31,
      "signal_str": "Bad system call",
      "status": 8,
      "time": 0,
      "extra": null,
    }
  ],
  "extra": null,
  "memory": 1756,
  "result": "syscall not allowed",
  "status": 8,
  "time": 0
}
```
