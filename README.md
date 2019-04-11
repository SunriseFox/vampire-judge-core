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

### 构建

+ 将 `./judgecore/default.json.sample`，复制到 `./judgecore/default.json`，修改其中需要的值
+ (Linux) 打开 build.sh，修改 `MOUNTFOLDER` 为本地一个已存在的目录，`MOUNTPOINT` 与 `$base` 一致即可，一般不需修改
+ (Windows) 打开 build.bat，修改 `MOUNTFOLDER` 为本地一个已存在的目录
+ 运行对应的 `build.sh` 或 `build.bat`

### 测试

+ 项目在 testcase 中提供了测试样例，只需要运行当前目录的 `./test.sh` 或 `test.bat` 即可。

### 更新

+ 如果只需更新内核或配置文件，运行 `./update.sh` 或者 `./update.bat`
+ 如果需要更新 Docker，`docker rm -f judgecore` 后重新构建

### Usage

+ 执行 `docker exec judgecore ./judgecore <配置文件.json>`（从文件读取配置） 或 `docker exec -ti judgecore ./judgecore stdin` （从 stdin 读取配置）即可。支持多个 json、stdin、默认配置文件自动合并，**参数在后的配置覆盖参数在前的配置，覆盖默认配置**。评测的结果在 $output 的 result.json。
+ 执行 `docker exec judgecore ./compiler <配置文件.json>` 编译 special judge 程序。

### Configuration File

需要至少 3 个配置文件才能运行：

+ 一个可接受的 **默认配置文件** （位于 ./judgecore/conf/default.json，[参考](https://github.com/SunriseFox/vampire-judge-core/blob/master/judgecore/conf/default.json.sample)）
+ 一个可接受的 **语言配置文件** （位于 ./judgecore/conf/lang_spec.json，[参考](https://github.com/SunriseFox/vampire-judge-core/blob/master/judgecore/conf/lang_spec.json)）
+ 至少一个运行时配置文件

+ 拼接示例

  ```json5
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
    // 编译器参数，期待数组 (argc[1] - argc[n])、字符串 (argc[1])
    // 此处额外可用 $customArgs，规则详见 default.json 中的规则
    "cargs": ["-DONLINE_JUDGE", "-pthread", "-O2", "-static", "-std=c++14", "-fno-asm", "-Wall", "-Wextra", "-o", "$exec", "$code"],
    // 预编译脚本，期待字符串，sh 格式（如果存在，设置 $script，需手动执行）
    // 此处额外可用 $customArgs，规则详见 default.json 中的规则
    "cscript": [],
    // 可执行文件，期待字符串（直接执行），数组（拼接为 sh 格式的脚本），null（默认为 $exec）
    "executable": "$exec",
    // 运行时参数，期待数组 (argc[1] - argc[n])、字符串 (argc[1])
    // 此处额外可用 $case，$customArgs
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
    // 语言资源限制额外设置，即：
    // 对应项，直接替换 config 中的限制
    // 对应项+，额外增加限制
    // 对应项*，额外乘上限制
    "patch": {
      // 2 倍限制内存
      "max_memory*": 2,
      // 额外 1 秒执行时间
      "max_time+": 1000,
      // 最多 2 线程
      "max_thread": 2
    }
  }
]
```

+ 默认配置文件格式如下：

```json5
{
  // 输出很多调试信息（真的很多）
  "debug": false,
  // 任意一些字段，可被类似 $pid 的方式引用，如不引用可任意删除，如引用其他字段可自行添加
  // 引用未定义的字段将会依样保留，并向 stderr 输出对应信息
  "pid": 9001,
  "sid": null,
  "filename": ["main.", "$lang_ext"],
  // 该项于运行时设置，代表正在测试的是第 i 组数据
  // 此处的设置会被覆盖
  "case": ["$", "case"],
  // 语言名或语言 ID
  "lang": "c",
  // 下面三项运行时根据 lang_spec 自动设置
  "lang_id": null,
  "lang_name": null,
  "lang_ext": null,
  // [可选] 编译器额外配置
  // 当 lang_spec 中对应项为 null 时，取此处配置
  // 当 lang_spec 中对应项为 false 时，跳过该项且此处不可设置
  // 否则，此处不可设置
  // 但，对于 cargs 和 cscript 和 eargs：
  // 当 lang_spec 中存在 1 个 $customArgs 时，将该配置对应的<期待类型>插入至这一位置
  // 当 lang_spec 中存在 n 个 $customArgs 时，将该配置数组对应第 i 个<期待类型>插入至这一位置
  // 如果此处对应项不存在，则直接将 $customArgs 移除
  // 例如，lang_spec 的 cargs 为 ["$customArgs", "-o", "$exec", "$code", "$customArgs"]
  // 此处 cargs 为 [["-O2"], ["-Wall", "-Wextra"]] 时，拼接完毕为
  // ["-O2", "-o", "<exec>", "<code>", "-Wall", "-Wextra"]
  // 例如，lang_spec 的 cscript 为 ["$customArgs", ", ", "$customArgs"]
  // 此处的 cscript 为 ["Hello", "$pid"]，则拼接完毕为
  // "Hello, 9001"
  // 如果此处不是数组或它的第 i 项不是<期待类型>，则对应 $customArgs 将被直接移除
  "variant": {
    // 字符串。
    "compiler": "gcc",
    // 数组
    "cargs": ["-DONLINE_JUDGE", "-lpthread", "-O2", "-static", "-std=c11", "-fno-asm", "-Wall", "-Wextra", "-o", "$exec", "$code"],
    // 数组
    "cscript": [],
    // 字符串
    "executable": "$exec",
    // 数组，额外设置 $case 为当前测试为第 i 组数据
    "eargs": []
  },
  "max_time": 1000, // 数字，毫秒
  "max_real_time": 2000, // 数字，毫秒
  "max_time_total": 30000, // 数字，毫秒
  "max_memory": 65530, // 数字，千字节
  "max_output": 10000000, // 数字，字节
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
  },
  // 在编译 spj 过程中，路径只有 $base 和 $spj 可以被引用
  "spj": {
    "code": ["$spj", ".", "$lang_ext"],
    "target": "$spj"
  },
  // [可选, 数组] 这里可以提供每组数据的输入文件
  // 如果 spj 模式是 inline，可额外提供标准输入
  // 文件名不能含有 /，置于用户程序工作目录且对用户程序只读。
  "inline": [{
    "stdin": "1 2\n",
    "fs": {
      "hello.txt": "Hello world!\n"
    }
  }]
}

```

+ spj 编译逻辑与上述相同，但使用 spj 中的 code 和 target
+ 编译的结果在 STDOUT，如果编译成功，返回 0，否则返回 1

```json5
{
  "debug": true,
  "lang": "c++",
  // default.json 的 spj 可引用此处值
  "pid": 9002,
  // 可选，覆盖默认设置
  "code": null,
  // 可选，覆盖默认设置
  "target": null
}
```

+ 编译输出

```json5
{
  "compiler": "",
  "success": true,
  "target": "/mnt/data/judge/9003"
}
```

+ Special Judge 调用参数：

```
如果是 compare，将在用户程序执行结束后运行，参数为
< = /dev/null
argv[1] = 输入，该组数据的 stdin
argv[2] = 输入，该组数据的 stdout
argv[3] = 输入，用户程序输出的 execout
argv[4] = 输入，如果用户程序写了文件，存放用户程序写入的文件的文件夹
> = 输出，写入结果 json 的 detail[i]:extra

如果是 interactive，将稍早于用户程序运行，参数为
< = 用户程序的 stdout
argv[1] = 输入，该组数据的 stdin
argv[2] = 输入，该组数据的 stdout
argv[3] = 输出，写入结果 json 的 detail[i]:extra
argv[4] = 输入，如果用户程序写了文件，存放用户程序写入的文件的文件夹
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
      // 当 spj 为 inline 时特有字段，每项最多读取 1000 字节
      "inline": {
        // 用户程序的标准输出
        "stdout": "3\n",
        // 用户写文件时的特有字段
        "fs": {
          "hi.txt": "Hello world!"
        }
      },
      // 当 spj 为 compare/interactive 时，为特殊评测程序的输出
      // 否则可能为内核输出的备注信息
      "extra": "ok",
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
