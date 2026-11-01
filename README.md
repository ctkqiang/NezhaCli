# 哪吒网络安全终端 · Nezha CLI

> 在阴影中观察，在授权下行动。

`nezha` 是一个面向 **Termux / Android ARM64 / 非 Root** 的集中式战术控制台。它把侦察、Web 审计、TLS/DNS/WHOIS、局域网发现、ESP 协处理器无线操作收进同一个 msfconsole 风格界面，而不是给每个外部工具套一层编号菜单。

控制台骨架取自作者 [SanTaiZi](https://github.com/ctkqiang/SanTaiZi) 的注册表、加载器与命令模型；无线路径按 [wifisec](https://github.com/ctkqiang/wifisec) 的 ESP 串口协议和 802.11 帧格式在 Go 进程内重写，不依赖 `wifisec` 二进制。

---

## 这不是外部工具启动器

项目坚持三条基线：

1. **原生优先**：端口扫描、服务指纹、DNS、WHOIS、子域枚举、局域网发现、HTTP 安全头、TLS 证书、ESP 串口协议与 deauth/disassoc 帧构造全部在进程内完成。
2. **单二进制**：原生模块零第三方 Go 依赖，`CGO_ENABLED=0`，可直接交叉编译为 Linux/ARM64 静态 ELF。
3. **授权闸门**：`wifi_deauth`、`wifi_brute`、`wifi_clone`、`cve_2025_14847`、`cve_2025_4334`、`cve_2025_66478` 以及所有外部模块在执行前必须输入 `yes` 确认；空回车、`y`、`YES!` 都视为拒绝。

只有一种情况会调用外部进程：你显式把可执行文件放进 `modules/bin`，并且该文件实现了 SanTaiZi 的 `--info` / `--execute` 协议。原生模块不会调用 `nmap`、`sqlmap`、`aircrack-ng` 或任何系统命令。

---

## 当前状态

**v0.7.0：控制台界面重做。**

- 横幅改为 metasploit 风格能力清单：启动即列出每个类别内置的模块数量，一眼看清本终端有什么能力。
- `show modules` 按类别分组展示，模块名按类别着色，影响级别以红色徽标标注。
- `show categories` 输出能力分布条形图，直观对比各方向能力密度。
- 表格、段落标题与模块卡片全面着色：灰边框、青表头、红必填项、红影响提示。
- 选中高影响模块时提示符中的模块名变红，执行前强制 yes 授权确认。
- 表格与横幅按终端宽度自适应，窄屏手机不再错位。
- 启动后打印三步上手引导，全部界面文字为中文。

**v0.6.0：战场脚本化与基础工具。**

- 31 个原生模块：在 v0.5.0 基础上新增战场基础工具。
- `hash`：MD5/SHA1/SHA256 文件与数据完整性校验（含期望值比对）。
- `encode`：base64 / hex / URL 编解码，hex 解码附原始字节预览。
- `random`：crypto/rand 口令与令牌生成，支持 upper/lower/digits/symbols/hex/all 字符集。
- `connect`：一次性 TCP 原始交互（文本/hex 发送 + hex/文本双栏响应回显），替代 nc。
- `http`：原始 HTTP 请求构造与回显（任意方法、请求头、内联或文件请求体）。
- `crunch`：按字符集与长度区间流式生成口令字典，内存占用恒定。
- 脚本命令：`echo`、`sleep`、`source`、`repeat`、`watch`、`save`/`load`；`-c` 支持 `@脚本文件`，模块失败时进程退出码为 1。
- 模块内部 panic 由引擎恢复并转换为错误，控制台永不崩溃。

**v0.5.0：原生集成作者 Go 工具链。**

- wifisec：ESP 协处理器路径（`esp`/`wifi_list`/`wifi_scan`/`wifi_deauth`/`wifi_brute`/`wifi_clone`）。
- vecmap：向量数据库只读指纹、集合枚举、CVE 版本关联与 ATT&CK 映射（`vecmap`）。
- BlindSQL：盲注 payload 字典库与过滤（`payloads`）。
- MITRERedTeam：BB01-BB25 战术与 27 条技术目录、执行器到原生模块的映射（`mitre`）。
- CVE-Exploits：MongoBleed（`cve_2025_14847`）、WordPress 提权验证（`cve_2025_4334`）、React2Shell 检测（`cve_2025_66478`）三个 Go PoC 原生移植 + 全库目录（`cve`）。
- QianKunQuan：CMS/WAF/技术栈指纹（`webfinger`）与 Markdown 报告导出（`report` 命令）。
- SanTaiZi：注册表、加载器、控制台命令模型与外部模块协议。
- msfconsole 风格命令：`search`、`use`、`show options`、`set`、`run`、`back`、`sessions`、`report`。
- 802.11 管理帧纯字节构造；ESP 协议纯 Go 编解码，均有独立测试。
- 全部测试集中在 `test/`，不散落在生产代码目录。

---

## 快速开始

### Termux / Android ARM64

```bash
pkg update
pkg install golang git make
git clone https://github.com/ctkqiang/NezhaCli.git
cd NezhaCli
make build
./bin/nezha
```

`make build` 使用项目要求的静态交叉编译参数：

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -trimpath -ldflags="-s -w -extldflags '-static'" \
  -o bin/nezha ./cmd/nezha
```

在 x86 Linux 或 macOS 上同样可以构建，产物是 Linux/ARM64 二进制，需要复制到 Termux 运行。

### 本机开发

```bash
make run          # go run ./cmd/nezha
make build-local  # 当前主机架构；macOS 上不包含 ESP 串口驱动
make test         # 运行全部测试
go test -race ./test/...
go vet ./...
```

---

## 第一次进入控制台

```text
$ ./bin/nezha

            ▂▃▅▇█▇▅▃▂
      ▂▃▅▇█▀         ▀█▇▅▃▂
▂▃▅▇█▀                   ▀█▇▅▃▂
   ███████████████████████████
                        哪 吒 网 络 安 全 终 端
                        战 术 控 制 台  ·  v0.7.0

 ============================================================================
=[ 哪吒网络安全终端 v0.7.0 ]
+ -- --=[ 侦察 9 个 · Web 9 个 · 系统 6 个 · 无线 6 个 · 蓝牙 1 个
+ -- --=[ 内置 31 个模块 · 零外部依赖 · 无需再安装任何工具
 ============================================================================

                      在阴影中观察，在授权下行动。

nezha > show modules      # 按类别分组列出全部内置能力
nezha > use wifi_scan
nezha (wifi_scan) > show options
nezha (wifi_scan) > set PORT /dev/ttyUSB0
nezha (wifi_scan) > run
```

选中模块后，提示符会带上模块名，避免在多个模块之间误执行。敏感参数（名称包含 `PASS`、`TOKEN`、`SECRET`、`KEY`、`COOKIE`）在 `show options` 与 `env` 中只显示 `********`。

### 控制台命令

| 命令 | 用途 |
| --- | --- |
| `help [命令]` | 查看总览或单条命令用法 |
| `search <关键词>` | 按名称、别名、类别、描述检索；多关键词为与关系 |
| `show modules` | 列出全部模块与序号 |
| `show options` | 查看当前模块参数 |
| `show categories` | 查看类别与模块数量 |
| `show globals` / `env` | 查看全局参数与当前模块参数 |
| `use <序号\|名称>` | 选中模块并载入默认参数 |
| `info` | 查看当前模块详情 |
| `set <参数> <值>` | 设置当前模块参数；含空格的值用双引号包裹 |
| `setg <参数> <值>` | 设置全局参数，切换模块后仍生效 |
| `unset <参数>` / `unsetg <参数>` | 清除当前模块参数或全局参数 |
| `run` / `exploit` | 执行当前模块；主动模块会要求授权确认 |
| `back` | 取消模块选择 |
| `sessions` | 查看本次控制台会话的执行记录 |
| `report [文件]` | 导出本次会话执行记录为 Markdown 报告 |
| `repeat <次数> <间隔> <命令>` | 周期性重复执行命令，Ctrl+C 中断 |
| `watch <间隔> <命令>` | 无限轮询执行命令，Ctrl+C 停止 |
| `sleep <时长>` | 脚本休眠，例如 `sleep 2s` |
| `echo <文本>` | 脚本输出文本 |
| `source <脚本文件>` | 逐行执行脚本文件 |
| `save / load <文件>` | 保存 / 恢复控制台状态（JSON） |
| `history` | 查看命令历史；`history -c` 清空 |
| `banner` / `dashboard` | 重绘横幅或仪表盘 |
| `clear` / `cls` | 清屏 |
| `version` | 显示版本与作者 |
| `exit` / `quit` / `q` | 退出控制台 |

运行模块时按 `Ctrl+C` 只取消当前模块；空闲时按 `Ctrl+C` 只提示退出方式，不会杀死控制台。模块内部 panic 由引擎恢复并记录为失败，控制台永不崩溃。

### 脚本模式

`-c` 接受分号或换行分隔的命令，引号内的分号不会被拆分；管道与非终端输出会自动关闭 ANSI 颜色。脚本以 `@` 开头时从文件读取命令；模块执行失败时进程以退出码 1 结束，便于接入流水线。

```bash
# 列出模块后退出
./bin/nezha -l

# 启动时选中模块，再执行脚本
./bin/nezha -m dns -c "set DOMAIN example.com; run"

# 一条命令完成 Web 审计并查看会话
./bin/nezha -c "use web; set URL https://example.com; run; sessions"

# 从脚本文件执行
./bin/nezha -c @recon.nezha

# 周期存活探测：每 5 秒探测一次网关，共 6 次
./bin/nezha -c "use connect; set HOST 192.168.1.1; set PORT 80; repeat 6 5s run"

# 自定义外部模块目录
./bin/nezha -modules ./modules/bin -c "show modules"
```

### 命令行参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-c` | 空 | 执行分号或换行分隔的控制台命令后退出 |
| `-m` | 空 | 启动时选中模块，例如 `-m portscan` |
| `-modules` | `modules/bin` | SanTaiZi 兼容外部模块目录 |
| `-l` | `false` | 列出全部模块后退出 |
| `-no-color` | `false` | 禁用 ANSI 颜色 |
| `-debug` | `false` | 输出调试日志 |
| `-version` | `false` | 显示版本并退出 |

---

## 原生模块

### 侦察

| 模块 | 作用 | 关键参数 |
| --- | --- | --- |
| `portscan` | 单主机、域名或 CIDR 的并发 TCP connect 扫描 | `TARGET`、`PORTS`（支持 `22,80,443` 与 `1-1024`）、`TIMEOUT`、`WORKERS`、`BANNER` |
| `service` | 读取明文服务首段数据并按 SSH/HTTP/FTP/SMTP/MySQL/Redis 等特征归类 | `TARGET`、`PORTS`、`TIMEOUT`、`WORKERS` |
| `dns` | A、AAAA、CNAME、MX、NS、TXT 记录查询 | `DOMAIN` |
| `whois` | TCP 43 查询域名或 IP 的注册信息，自动发现权威服务器 | `TARGET`、`SERVER`、`TIMEOUT`、`RAW` |
| `subdomain` | 内置字典 + 自定义字典 + crt.sh 证书透明日志，DNS 并发验证并检测通配符 | `DOMAIN`、`WORDLIST`、`THREADS`、`CRT` |
| `lan` | 枚举本机接口、推断 `/24` 网段、TCP 探测活跃主机 | `CIDR`、`DISCOVER`、`PORTS`、`TIMEOUT`、`WORKERS` |

```text
nezha > use portscan
nezha (portscan) > set TARGET 192.168.1.0/24
nezha (portscan) > set PORTS 22,80,443,8000-8100
nezha (portscan) > run
```

`portscan` 走普通 TCP connect，不需要 `CAP_NET_RAW`；只开放 UDP 或被防火墙静默丢弃的主机会漏报。

### Web

| 模块 | 作用 | 关键参数 |
| --- | --- | --- |
| `web` | HTTP 安全响应头、Cookie 属性、robots.txt、sitemap.xml、security.txt、OPTIONS 方法 | `URL`、`TIMEOUT`、`DEEP` |
| `tls` | TLS 协议版本、密码套件、证书主题、签发者、有效期、SAN 与信任状态 | `TARGET`、`PORT`、`TIMEOUT` |
| `webdir` | 内置字典探测管理后台、`.git`、`.env`、备份文件、Swagger、Actuator 等高频暴露面 | `URL`、`CODES`、`THREADS`、`TIMEOUT` |

```text
nezha > use web
nezha (web) > set URL https://example.com
nezha (web) > run

nezha > use tls
nezha (tls) > set TARGET example.com
nezha (tls) > run

nezha > use webdir
nezha (webdir) > set URL https://example.com
nezha (webdir) > set CODES 200,204,301,302,403
nezha (webdir) > run
```

`web` 与 `webdir` 只做只读请求与路径探测，不发送 SQL 注入、XSS、命令注入等攻击载荷。

### 无线

| 模块 | 作用 | 关键参数 |
| --- | --- | --- |
| `esp` | 打开串口、执行 DTR/RTS 复位、PING/PONG 握手，报告固件版本、频段能力与可选扫描 | `PORT`、`SCAN` |
| `wifi_list` | 本机无线接口、链路状态、`/proc/net/wireless` 信号质量；`ESP=true` 时改走协处理器扫描 | `ESP`、`PORT` |
| `wifi_scan` | 通过 ESP 协处理器扫描周边 AP，返回 SSID、BSSID、信道、RSSI | `PORT`、`SORT`、`MIN_RSSI`、`HIDDEN` |
| `wifi_deauth` | 通过 ESP 注入广播/定向 deauth 或 disassoc 管理帧 | `BSSID`、`CHANNEL`、`STATION`、`FRAME`、`COUNT`、`INTERVAL`、`REASON` |
| `wifi_brute` | 通过 ESP 逐条尝试 WiFi 密码字典，命中即停 | `SSID`、`WORDLIST`、`DELAY`、`MAX`、`STOP_ON_SUCCESS` |
| `wifi_clone` | 让 ESP 开启同名同密码 SoftAP，查询在线设备或定时监控 | `ACTION`（`up/down/status/watch`）、`SSID`、`PASSWORD`、`CHANNEL`、`WATCH`、`DOWN_ON_EXIT` |

`wifi_deauth`、`wifi_brute`、`wifi_clone` 是高影响模块，`run` 后会显示授权确认，必须输入 `yes`。

### 系统与蓝牙

| 模块 | 作用 | 关键参数 |
| --- | --- | --- |
| `sysinfo` | 主机名、系统、架构、UID、Root 状态、发行版、内核、网络接口、出站连通性 | `TARGETS`、`TIMEOUT` |
| `bt` | 读取 `/sys/class/bluetooth` 下的 HCI 适配器信息，只做被动枚举 | `SYSFS` |

```text
nezha > use sysinfo
nezha (sysinfo) > run

nezha > use bt
nezha (bt) > run
```

Android 的非 Root Termux 通常无法读取蓝牙 sysfs；模块会给出明确说明，这属于系统权限边界，不是模块故障。

### 战场基础工具

| 模块 | 作用 | 关键参数 |
| --- | --- | --- |
| `hash` | MD5/SHA1/SHA256 文件与数据完整性校验，可选期望值比对 | `INPUT`、`ALGO`、`EXPECT` |
| `encode` | base64 / hex / URL 编解码 | `ACTION`、`ALGO`、`VALUE` |
| `random` | crypto/rand 口令与令牌生成 | `LENGTH`、`CHARSET`、`COUNT` |
| `connect` | 一次性 TCP 原始交互（文本/hex 发送，hex+文本双栏回显） | `HOST`、`PORT`、`SEND`、`HEX`、`TIMEOUT`、`WAIT` |
| `http` | 原始 HTTP 请求构造与回显 | `URL`、`METHOD`、`HEADERS`、`BODY`、`BODYFILE`、`SHOW_BODY` |
| `crunch` | 字符集×长度区间流式口令字典生成 | `CHARSET`、`MIN`、`MAX`、`OUTPUT`、`LIMIT` |

```text
nezha > use hash
nezha (hash) > set INPUT ./nezha
nezha (hash) > set ALGO sha256
nezha (hash) > run

nezha > use connect
nezha (connect) > set HOST 10.0.0.1
nezha (connect) > set PORT 22
nezha (connect) > run

nezha > use crunch
nezha (crunch) > set CHARSET abc123
nezha (crunch) > set MIN 1
nezha (crunch) > set MAX 4
nezha (crunch) > set OUTPUT ~/dict.txt
nezha (crunch) > run
```

`crunch` 单次上限 1000 万行，生成中途 Ctrl+C 安全中止并保留已写入内容。

### 作者 Go 工具原生移植

这组模块是作者工具链在本控制台内的**真实代码移植**，不是外部调用：

| 模块 | 来源 | 作用 | 关键参数 |
| --- | --- | --- | --- |
| `vecmap` | vecmap | 向量数据库只读指纹、集合/索引枚举、CVE 版本关联与 ATT&CK 映射；支持 Qdrant、Milvus、Weaviate、Chroma、Elasticsearch、OpenSearch、Typesense、Vespa、Redis | `TARGET`、`ADAPTER`、`TIMEOUT`、`DEEP` |
| `payloads` | BlindSQL | 内置盲注 payload 字典（布尔/时间/UNION/注释绕过族），关键词过滤与外部字典加载 | `QUERY`、`WORDLIST`、`LIMIT` |
| `mitre` | MITRERedTeam | BB01-BB25 战术与 27 条技术目录，执行器映射到原生模块 | `TACTIC`、`QUERY`、`TECHNIQUE` |
| `cve` | CVE-Exploits | PoC/Exploit 库目录，标明语言与内置模块映射 | `QUERY`、`ID` |
| `cve_2025_14847` | CVE-Exploits | MongoBleed：OP_COMPRESSED 内存泄露探测 + 版本结论表 | `HOST`、`PORT` |
| `cve_2025_4334` | CVE-Exploits | WordPress 注册接口 role=administrator 提权验证 | `URL`、`FORM`、`USERNAME`、`EMAIL`、`PASSWORD` |
| `cve_2025_66478` | CVE-Exploits | React2Shell（Next.js）RSC 反序列化检测 | `URL`、`ACTION`、`TIMEOUT`、`VERBOSE` |
| `webfinger` | QianKunQuan | 21 款 CMS、14 款 WAF/CDN 与技术栈指纹识别 | `URL`、`TIMEOUT`、`UA` |

```text
nezha > use vecmap
nezha (vecmap) > set TARGET 10.0.0.5:6333
nezha (vecmap) > run

nezha > use mitre
nezha (mitre) > set TACTIC BB01
nezha (mitre) > run

nezha > use payloads
nezha (payloads) > set QUERY sleep
nezha (payloads) > run

nezha > use webfinger
nezha (webfinger) > set URL https://example.com
nezha (webfinger) > run
```

`cve_2025_14847`、`cve_2025_4334`、`cve_2025_66478` 是高影响模块，`run` 后必须输入 `yes`。三个 PoC 的逻辑与判定阈值均与上游仓库一致；`vecmap` 保持上游“只读铁律”，只发 GET/HEAD/OPTIONS 与只读 POST。

会话结束后用 `report` 导出评估报告：

```text
nezha > report assessment-2026.md
```

---

## ESP 协处理器路径

非 Root Android 没有 `CAP_NET_RAW`，不能创建 monitor 接口，也不能直接注入 802.11 管理帧。`nezha` 的主动无线能力全部交给 ESP8266/ESP32 协处理器：宿主机只写 USB 串口，射频工作在开发板上。

### 硬件与固件

| 项目 | 要求 |
| --- | --- |
| 开发板 | ESP8266（NodeMCU、Wemos D1 mini 等）或 ESP32 经典/C2/C3/S2/S3；ESP32-C5 额外支持 5GHz |
| 固件 | [wifisec](https://github.com/ctkqiang/wifisec) 的 `core/esp/esp.ino`，协议版本 v1 |
| 串口 | 115200 8N1；自动复位依赖 DTR/RTS |
| 数据线 | 必须是 USB 数据线，不能是纯充电线 |
| 频段 | 2.4GHz（信道 1-14）；ESP32-C5 支持 5GHz；6GHz 不支持 |
| 不支持 | Arduino UNO + WiFi Shield（NINA/WINC 没有开放原始帧注入 API） |

固件烧录流程、板型选择、晶振与供电排错见 wifisec 的 `docs/feature/wifi_deauth.md`。烧录完成后板载 LED 应先快闪三下，然后进入约 0.5 秒一次的心跳；没有心跳说明固件没有运行。

### 串口识别

模块会在 `PORT` 为空时自动探测唯一的 USB 串口，候选包括：

```text
/dev/ttyUSB*        /dev/ttyACM*        /dev/ttyCH343USB*
/dev/ttyXRUSB*      /dev/ttyHS*         /dev/cu.usbserial*
/dev/cu.SLAB_USBtoUART*                 /dev/cu.wchusbserial*
```

发现多个设备时不会猜测，必须显式设置：

```text
nezha > use esp
nezha (esp) > set PORT /dev/ttyUSB0
nezha (esp) > set SCAN true
nezha (esp) > run
```

macOS 常见端口是 `/dev/cu.usbserial-XXXX`；Linux 常见端口是 `/dev/ttyUSB0`、`/dev/ttyACM0`。

### Termux 的串口访问边界

ESP 路径不需要 Android 的 raw socket 或 `CAP_NET_RAW`，但 Termux 仍然必须能打开串口设备节点：

```bash
ls -l /dev/ttyUSB* /dev/ttyACM*
```

- 能看到设备节点且有读写权限：直接使用。
- 没有设备节点：先检查 OTG 数据线、供电和串口芯片驱动。
- 节点存在但 `Permission denied`：当前 ROM/内核没有把该节点开放给 Termux。当前实现直接打开 `/dev/ttyUSB*`，不经过 Android USB Host API，也不会绕过系统权限；此时需要 root、改用 Linux 主机，或使用能够把串口文件描述符交给程序的环境。
- 模块在打不开串口时会明确报错，不会静默假装成功。

### 验证与使用

先握手，再扫描，最后才执行主动操作：

```text
nezha > use esp
nezha (esp) > set SCAN true
nezha (esp) > run

nezha > use wifi_scan
nezha (wifi_scan) > set SORT rssi
nezha (wifi_scan) > run
```

deauth / disassoc：

```text
nezha > use wifi_deauth
nezha (wifi_deauth) > set BSSID aa:bb:cc:dd:ee:ff
nezha (wifi_deauth) > set CHANNEL 6
nezha (wifi_deauth) > set FRAME both
nezha (wifi_deauth) > set COUNT 32
nezha (wifi_deauth) > run
# 看到授权确认后输入 yes
```

在线密码字典：

```text
nezha > use wifi_brute
nezha (wifi_brute) > set SSID Lab
nezha (wifi_brute) > set WORDLIST ~/storage/shared/words.txt
nezha (wifi_brute) > set MAX 20
nezha (wifi_brute) > run
```

克隆 AP：

```text
nezha > use wifi_clone
nezha (wifi_clone) > set ACTION up
nezha (wifi_clone) > set SSID Lab
nezha (wifi_clone) > set PASSWORD lab12345
nezha (wifi_clone) > set CHANNEL 6
nezha (wifi_clone) > set WATCH 60s
nezha (wifi_clone) > run
```

### 协议边界

- WPA3 与 6GHz 网络强制启用 PMF，未认证的 deauth/disassoc 会被客户端直接丢弃；这是 802.11 协议约束，不是注入失败。
- 2.4GHz 开发板看不到 5GHz/6GHz 目标；5GHz 注入需要 ESP32-C5 固件。
- `wifi_brute` 单次尝试在主机侧最多等待 15 秒（`FrameRetryTimeout`），实际关联通常 2-5 秒；适合小规模、受控字典，不适合大字典高速喷洒。
- `wifi_clone` 会创建伪造接入点，属于高影响操作；只在书面授权范围内使用。
- 固件协议版本不一致时，`esp` 会拒绝继续，要求重新烧录匹配版本的固件。

---

## 与作者 Go 工具的关系

这张表描述的是**当前代码里的真实状态**，不是规划清单。未集成的能力不会出现在 `show modules` 里，也不会被伪装成已实现。

| 项目 | 原始能力 | 在本项目中的落地 | 状态 |
| --- | --- | --- | --- |
| [wifisec](https://github.com/ctkqiang/wifisec) | ESP 协处理器无线测试：扫描、deauth、brute、clone | `internal/wireless/esp` 串口协议/握手/注入/关联/克隆；`internal/wireless/ieee80211` 帧构造；`esp`、`wifi_list`、`wifi_scan`、`wifi_deauth`、`wifi_brute`、`wifi_clone` 六个模块 | **已原生集成（核心路径）** |
| [SanTaiZi](https://github.com/ctkqiang/SanTaiZi) | 模块化控制台、注册表、加载器、SDK、`modules/bin` | `internal/core`、`internal/structure`、`internal/model`；兼容 `--info` / `--execute` 的外部模块适配器 | **已集成架构与外部模块协议** |
| [vecmap](https://github.com/ctkqiang/vecmap) | 向量数据库指纹、只读探测、集合枚举、CVE 关联、ATT&CK 报告 | `pkg/vecmap` 后端（9 类厂商探测、集合枚举、内置 CVE 库与 MITRE 映射）+ `vecmap` 模块；gRPC/记录提取/SQLite 证据库未移植 | **已原生集成（只读核心）** |
| [BlindSQL](https://github.com/ctkqiang/BlindSQL) | 盲注 payload 加载器与 2465 行字典 | `payloads` 模块：内置代表性子集字典、关键词过滤、外部字典加载；完整上游字典见仓库 payload.txt | **已原生集成（字典库）** |
| [MITRERedTeam](https://github.com/ctkqiang/MITRERedTeam) | BB01-BB25 战术、27 条技术、目录驱动、证据链 | `mitre` 模块：战术/技术目录与执行器→原生模块映射；LLM 辅助与通知系统未移植 | **已原生集成（目录与映射）** |
| [CVE-Exploits](https://github.com/ctkqiang/CVE-Exploits) | CVE PoC/Exploit 集合 | `cve` 库目录 + 三个 Go PoC 原生移植：`cve_2025_14847`（MongoBleed）、`cve_2025_4334`（WordPress 提权）、`cve_2025_66478`（React2Shell 检测）；非 Go PoC 保留在仓库目录 | **部分原生集成（Go PoC + 目录）** |
| [QianKunQuan](https://github.com/ctkqiang/QianKunQuan) | 红队侦察、CVE/CNVD 索引、攻击路径、报告 | `webfinger` 模块（CMS/WAF/技术栈指纹）+ `report` 命令（Markdown 报告）；`portscan`/`service`/`subdomain`/`webdir` 覆盖侦察；CVE 库与攻击路径生成未移植 | **部分原生集成（指纹 + 报告）** |
| [NezhaSec](https://github.com/ctkqiang/NezhaSec) | DeepSeek 编排、外部工具执行器、TUI | 未集成；本项目不引入 LLM 自动编排，也不默认调用外部工具 | **设计参考** |

未直接集成的部分，处理原则如下：

1. **能纯 Go 重写的**：先在 `pkg/` 或 `internal/` 实现，再注册为原生模块。
2. **必须独立进程的**：只通过 `modules/bin` 适配层接入，执行前显示影响级别并要求 `yes`。
3. **会引入自动利用或大规模外联的**：默认不做，避免把一个侦察控制台变成不可审计的自动化攻击链。

---

## 外部模块适配层

外部模块是可选的，不是运行前置条件。适配协议来自 SanTaiZi SDK：

```text
modules/bin/
└── mytool
```

`mytool --info` 输出：

```text
name:mytool
description:示例外部模块
cnvd:CNVD-2024-0001
cve:CVE-2024-0001
option:TARGET:string:true:
option:MODE:string:false:fast
```

字段说明：

- `name`：模块名；缺失时回退为文件名。
- `description`：描述；首行会作为摘要。
- `cnvd` / `cve`：可选引用，展示在模块卡片中。
- `option:名称:类型:是否必填:默认值`：与 SanTaiZi SDK 一致，可重复多行；类型仅用于展示。

执行时控制台调用：

```bash
mytool --execute MODE=fast TARGET=example.com
```

规则：

- `--info` 读取超时为 5 秒；无效可执行文件只产生警告，不阻止控制台启动。
- 空参数不会传给外部模块。
- 外部模块的 `Impact` 固定为非空，因此 `run` 一定会要求输入 `yes`。
- 标准输出与标准错误直接写入控制台；取消运行时子进程会收到上下文取消。
- 只放你信任的本地二进制；这是显式的 `os/exec` 边界，原生模块不经过它。

---

## 非 Root Termux 能力边界

| 能力 | 非 Root Termux | 说明 |
| --- | --- | --- |
| TCP connect 端口扫描 | 可用 | 普通 socket |
| 服务 Banner 抓取 | 可用 | 普通 TCP 连接 |
| DNS / WHOIS | 可用 | 标准库解析器与 TCP 43 |
| HTTP 安全头 / TLS 证书 | 可用 | 标准 HTTP/TLS 客户端 |
| 子域名枚举 | 可用 | 内置字典 + DNS + 可选 crt.sh |
| 局域网 TCP 存活探测 | 可用 | 不依赖 ARP 原始套接字 |
| 本机接口 / 系统信息 | 可用（受系统限制） | 读取 `/sys`、`/proc` 与标准库 |
| 蓝牙适配器枚举 | 可用（受系统限制） | 读取 `/sys/class/bluetooth` |
| ESP 扫描 / 注入 / 关联 / 克隆 | 需 ESP 开发板 + 可打开的串口 | 射频在开发板上，宿主不需要 raw socket |
| 本机 WiFi monitor / 原生注入 | 不可用 | 需要 Root / `CAP_NET_RAW` |
| SYN 扫描 / masscan 风格 | 不可用 | 需要原始套接字 |
| UDP 扫描 | 未实现 | 当前只有 TCP connect |
| 蓝牙主动扫描 / 配对 | 不可用 | Android 蓝牙栈由系统服务管理 |
| 自动漏洞利用 | 不提供 | 没有 exploit runtime |

---

## 构建与测试

```bash
# 代码格式
gofmt -w cmd internal modules pkg test

# 静态检查
go vet ./...

# 全部测试
go test ./test/...

# 竞态检测
go test -race ./test/...

# Linux/ARM64 静态产物
make build
file bin/nezha
```

`file bin/nezha` 应显示 `ELF 64-bit LSB executable, ARM aarch64` 且为静态链接。`make build` 与项目要求的命令完全一致，不额外引入 CGO 或第三方依赖。

测试覆盖：

- 模块注册表、别名、检索、默认参数与类别。
- 控制台命令、引号解析、脚本模式、授权拒绝/接受、会话记录、敏感参数脱敏。
- CJK/ANSI/emoji 终端宽度与表格对齐。
- 网络工具函数、端口范围解析、CIDR 展开、MAC/URL 规范化。
- 802.11 deauth/disassoc 帧布局、radiotap、信标解析与边界检查。
- ESP 帧编码/解码、跨包累积、扫描条目、PONG、克隆结果与协议常量。
- 端口扫描、Banner、DNS、HTTP 安全头、标准文件、OPTIONS、TLS。
- 系统信息、接口、连通性、蓝牙枚举。
- vecmap：CVE 版本区间匹配、目标解析、厂商过滤与 MITRE 目录。
- mitre：25 条战术与 27 条技术目录完整性、过滤与详情输出。
- payloads：内置字典过滤；webfinger：CMS/WAF 指纹识别（httptest）。
- CVE 移植：MongoBleed 版本结论表、WordPress 载荷构造与判据、React2Shell 响应判据。
- report 命令的 Markdown 报告导出。
- 战场基础工具：hash 摘要与期望值校验、encode 编解码、random 字符集约束、connect 原始 TCP 交互、http 请求回显、crunch 组合完整性。
- 脚本命令：echo/sleep/repeat/watch/save/load 与 @脚本文件执行。
- 引擎 panic 恢复：模块 panic 被转换为错误而不击穿进程。
- 外部模块 `--info` / `--execute` 适配与无效模块警告。

需要真实 ESP 硬件的路径不在单元测试中伪造；协议层和帧层用纯字节测试覆盖。

---

## 项目结构

```text
cmd/nezha/                  入口、参数解析、控制台/脚本分发
internal/core/              注册表、加载器、外部模块适配
internal/structure/         控制台状态、命令、提示符、渲染
internal/engine/            参数校验、执行、会话结果
internal/model/             模块契约与参数读取
internal/text/              CJK/ANSI 感知的终端排版
internal/netutil/           目标规范化、CIDR、URL、MAC
internal/modulekit/         模块元数据与表格辅助
internal/wireless/ieee80211 802.11 管理帧构造与解析
internal/wireless/esp       ESP 串口协议、握手、注入、关联、克隆
modules/                    31 个原生模块（含作者工具移植）
pkg/config/                 应用元数据
pkg/logger/                 彩色战术日志
pkg/recon/                  端口扫描、Banner、DNS
pkg/web/                    HTTP 安全头、标准文件、TLS
pkg/system/                 系统、接口、蓝牙、连通性
pkg/vecmap/                 向量数据库指纹、集合枚举、CVE 库与 MITRE 映射
test/                       全部测试
docs/                       Termux 能力边界与外部工具对照
modules/bin/                可选外部模块目录（默认不存在）
```

---

## 文档

- [Termux 能力边界与原生模块手册](docs/TERMUX_TOOLS.md)：原生模块细节、ESP 固件/串口排错、非 Root 边界、作者 Go 工具集成状态、外部工具可选对照。

---

## 安全与法律声明

本项目仅用于**已获得明确授权的安全评估、资产盘点与防御验证**。

严禁用于：

- 未经授权的网络扫描、入侵或干扰。
- 对他人 WiFi、蓝牙设备、主机或 Web 系统进行未授权测试。
- 窃取数据、绕过访问控制、破坏系统或持久化控制。
- 对公共网络、第三方设备或任何不属于你的资产执行 deauth、克隆 AP、密码尝试等主动操作。

`wifi_deauth`、`wifi_brute`、`wifi_clone` 会中断无线服务、尝试关联目标 AP 或创建伪造接入点，可能造成服务中断、账户锁定或告警。使用前必须确认目标属于你或已获得书面授权，并遵守当地法律法规。作者不对任何滥用行为负责。

---

## 作者

**钟智强 ctkqiang**

- GitHub: <https://github.com/ctkqiang>
- 项目: <https://github.com/ctkqiang/NezhaCli>
- 无线上游: <https://github.com/ctkqiang/wifisec>
- 控制台上游: <https://github.com/ctkqiang/SanTaiZi>
