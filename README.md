## Vampire Judge Core

### Prerequisite

+ Docker (如果是 Windows 下的 Docker，必须选择 Hyper-V + Linux Container)

### Known Issues in Windows

+ 如果卷 /mnt/data 挂载在 Windows 目录下，Docker 无法进行文件权限控制，可能导致错误的用户程序有权读取该目录的任意文件
+ 如果卷 /mnt/data 挂载在 Windows 目录下，可能存在文件描述符泄露

### Known Issues in KVM / OpenVZ

+ OpenVZ 架构虚拟化无法运行这一内核
+ 不是所有的 KVM 都可以运行，我们需要完整的嵌套虚拟化权限。如果在测试的时候提示 `while attach: No Such Process` 等，大概率是因为你的虚拟化实现缺少 SYS_PTRACE 权限。

### Security Issus

+ 如果允许用户自定义编译器和编译指令，请务必小心，编译器仅在部分监视的情况下运行

### Build

+ (Linux) 打开 build.sh，修改 `MOUNTFOLDER` 为本地一个已存在的目录
+ (Windows) 打开 build.bat，修改 `MOUNTFOLDER` 为本地一个已存在的目录
+ 运行对应的 `build.sh` 或 `build.bat`

### 测试

+ 项目在 testcase 中提供了测试样例，只需要运行当前目录的 `./test.sh` 或 `test.bat` 即可。

### Usage

+ 执行 `docker exec judgecore ./judgecore <配置文件.json>`（从文件读取配置） 或 `docker exec -ti judgecore ./judgecore stdin` （从 stdin 读取配置）即可。支持多个 json、stdin、默认配置文件自动合并，**参数在后的配置覆盖参数在前的配置，覆盖默认配置**。评测的结果在 $output 的 result.json。
+ 执行 `docker exec judgecore ./compiler <配置文件.json>` 编译 special judge 程序。

### Configuration File

需要至少 3 个配置文件才能运行：

+ 一个可接受的 **默认配置文件** （位于 ./judgecore/conf/default.json，[参考](https://github.com/SunriseFox/vampire-judge-core/blob/master/judgecore/conf/default.json)）
+ 一个可接受的 **语言配置文件** （位于 ./judgecore/conf/lang_spec.json，[参考](https://github.com/SunriseFox/vampire-judge-core/blob/master/judgecore/conf/lang_spec.json)）
+ 至少一个运行时配置文件

+ 拼接示例

  ```json
  {
    "pid": 1001,
    "variant": {
      // 期待字符串
      "compiler": ["$pid", "hello"],
      // 期待数组
      "cargs": ["$pid", "hello"],
      // 期待数组
      "eargs": [["$pid", "hello"]]
    },
    "path": {
      // 期待路径
      "code": ["$pid", "hi"],
      "exec": "$code"
    }
  }
  ```
  + code 期待路径，这一部分会被替换为 `"1001/hi"` （用 / 拼接）
  + compiler 期待字符串，这一部分会替换为 `"1001hello"` （拼接）
  + cargs 期待数组，因此这一部分会被替换为 `["1001", "hello"]` （外层数组保持不变）
  + eargs 期待数组，因此这一部分会被替换为 `["1001hello"]` （内层数组拼接）
  + exec 期待字符串，引用了 code，优先使用同级的 path->code 的值，因此为`"1001/hi"`。

+ 语言配置文件如下（部分）：

```json5
[
  {
    // 语言 ID
    "id": 0,
    // 语言名
    "name": "c++",
    // 代码扩展名
    "ext": "cpp",
    // 编译器可执行文件，false(bool) 则强制跳过编译阶段
    "compiler": "g++",
    // 编译器参数，期待数组、字符串（自动作为 argc[1]）
    "cargs": ["-DONLINE_JUDGE", "-pthread", "-O2", "-static", "-std=c++14", "-fno-asm", "-Wall", "-Wextra", "-o", "$exec", "$code"],
    // 预编译脚本，期待字符串，sh 格式（如果存在，设置 $script，需手动执行）
    "cscript": [],
    // 可执行文件，期待字符串（直接执行），数组（拼接为 sh 格式的脚本），null（默认为 $exec）
    "executable": "$exec",
    // 运行时参数，期待数组、字符串（自动作为 argc[1]）
    "eargs": []
  }, {
    "id": 1,
    "name": "javascript",
    "ext": "js",
    "compiler": false,
    "cargs": null,
    "cscript": null,
    "executable": "/usr/bin/v8/d8",
    "eargs": "$code",
    "patch": {
      "max_memory": 524288,
      "max_time+": 1000
    }
  }
]
```

+ 默认配置文件内容如下：

```json5
{
  // 输出很多调试信息（真的很多）
  "debug": false,
  // 任意字段，可被类似 $pid 的方式引用，如不引用可任意删除，如引用其他字段可自行添加
  "pid": null,
  "sid": null,
  "filename": null,
  // 语言名或语言 ID
  "lang": "c",
  // 编译器额外配置
  "variant": {
    // 字符串，出于安全考虑，只有当 lang_spec 中该项为 null 时才可配置。 false 跳过编译。
    "compiler": "gcc",
    // 数组
    "cargs": ["-DONLINE_JUDGE", "-lpthread", "-O2", "-static", "-std=c11", "-fno-asm", "-Wall", "-Wextra", "-o", "$exec", "$code"],
    // 数组
    "cscript": [],
    // 字符串
    "executable": "$exec",
    // 数组
    "eargs": []
  },
  "max_time": 1000, // 数字，毫秒
  "max_real_time": 2000, // 数字，毫秒
  "max_time_total": 30000, // 数字，毫秒
  "max_memory": 65530, // 数字，千字节
  "max_output": 10000000, // 数字字节
  "max_thread": 4, // 数字，核心/线程/进程数
  "continue_on": ["accepted", "presentation error"], // 枚举数组或布尔
  "test_case_count": 1, // 数字，自动取 $stdin 中的 1~c 的 .in 文件作为标准输入，0 不测
  "spj_mode": "no", // 枚举，可能的值为 "no", "inline"（从 json 读入，输出到 json），"compare" 自定义比较程序， "interactive" 自定义交互评测程序
  // 期待 object，内部均期待路径；不存在的值可任意指定并自行引用
  "path": {
    "base": "/mnt/data",
    "code": ["$base", "code", "$pid", "$sid", "$filename"],
    "log": ["$temp"],
    "output": ["$base", "result", "$pid", "$sid"],
    "stdin": ["$base", "case", "$pid"],
    "stdout": ["$stdin"],
    "temp": ["/tmp", ["judge-", "$pid", "-", "$sid"]],
    "exec": ["$temp", "main"],
    "spj": ["$base", "judge", "$pid"]
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
