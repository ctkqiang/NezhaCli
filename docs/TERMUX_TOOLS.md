# Termux 能力边界与原生模块手册

> 目标环境：Termux / Android ARM64 / 非 Root。
>
> 本文回答三个问题：
>
> 1. 哪些能力在手机上开箱可用；
> 2. 主动无线能力到底需要什么硬件和权限；
> 3. 作者的 Go 工具链里，哪些已经真正进了本项目，哪些没有。
>
> 本文描述的是**当前代码的真实状态**，不是路线图。未实现的能力不会出现在 `show modules` 里。

---

## 0. 先看结论

| 你想做的事 | 需要什么 | 对应模块 |
| --- | --- | --- |
| 扫端口、抓 Banner、查 DNS/WHOIS、枚举子域 | 一台能跑 Termux 的手机 | `portscan` `service` `dns` `whois` `subdomain` |
| 审计 HTTP 安全头、TLS 证书、常见敏感路径 | 同上 | `web` `tls` `webdir` |
| CMS/WAF/技术栈指纹识别 | 同上 | `webfinger` |
| 盲注 payload 字典 | 同上 | `payloads` |
| 文件完整性校验 / 编解码 / 随机令牌 | 同上 | `hash` `encode` `random` |
| 原始 TCP 交互与原始 HTTP 请求 | 同上 | `connect` `http` |
| 口令字典生成 | 同上 | `crunch` |
| 周期探测 / 轮询 / 脚本执行 | 同上 | `repeat` `watch` `sleep` `source` `save` `load` |
| MITRE 战术/技术目录与执行映射 | 同上 | `mitre` |
| 向量数据库攻击面评估 | 同上（只读 HTTP/TCP 探测） | `vecmap` |
| CVE PoC 验证（MongoBleed/WordPress/React2Shell） | 同上，且必须已获书面授权 | `cve` `cve_2025_14847` `cve_2025_4334` `cve_2025_66478` |
| 导出评估报告 | 同上 | `report` 命令 |
| 发现局域网存活主机 | 同上（普通 TCP connect） | `lan` |
| 查看本机接口、系统信息、蓝牙适配器 | 同上，部分信息受 Android 限制 | `sysinfo` `bt` |
| 扫描周边 WiFi | ESP8266/ESP32 + 可打开的串口 | `esp` `wifi_scan` `wifi_list` |
| deauth / disassoc / 在线密码尝试 / 克隆 AP | 同上，且必须已获书面授权 | `wifi_deauth` `wifi_brute` `wifi_clone` |
| 本机 monitor 模式、SYN 扫描、抓包、ARP 欺骗 | Root + `CAP_NET_RAW` | **不提供** |
| 自动漏洞利用、CVE 一把梭 | 本项目没有 exploit runtime | **不提供** |

一句话：**侦察与 Web 审计是原生能力；主动无线是协处理器能力；需要 Root 的原始套接字能力，本项目不假装能做。**

---

## 1. 原生模块手册

原生模块全部在 Go 进程内执行，不调用 `nmap`、`sqlmap`、`aircrack-ng`、`iw` 等外部命令。参数在控制台里用 `set` 设置，`run` 执行。

通用工作流：

```text
nezha > search 关键词
nezha > use 模块名
nezha (模块名) > show options
nezha (模块名) > set 参数 值
nezha (模块名) > run
nezha (模块名) > sessions
```

### 1.1 侦察类

#### `portscan` — 并发 TCP connect 扫描

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `TARGET` | 必填 | 主机、域名或 CIDR；多个目标用逗号分隔 |
| `PORTS` | `22,80,443,445,3389` | 支持 `22,80,443` 与 `1-1024` |
| `TIMEOUT` | `400ms` | 单次连接与 Banner 读取超时 |
| `WORKERS` | `256` | 并发协程数，上限 512 |
| `BANNER` | `true` | 是否读取服务首段数据 |

```text
nezha > use portscan
nezha (portscan) > set TARGET 192.168.1.0/24
nezha (portscan) > set PORTS 22,80,443,8000-8100
nezha (portscan) > set TIMEOUT 300ms
nezha (portscan) > run
```

边界：

- 走普通 `connect(2)`，不需要 `CAP_NET_RAW`，非 Root 可用。
- 只有 TCP；UDP 扫描未实现。
- 只输出成功建立 TCP 连接的端点；被防火墙静默丢弃的端口不会出现，也不区分 `closed` 与 `filtered`。
- 大网段 + 大端口范围会产生大量连接，手机上建议先用小范围确认网络质量。

#### `service` — 服务指纹

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `TARGET` | 必填 | 主机、域名或 CIDR |
| `PORTS` | `21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443` | 待识别端口 |
| `TIMEOUT` | `600ms` | 连接与读取超时 |
| `WORKERS` | `48` | 并发数 |

按 Banner 特征归类 SSH、HTTP、FTP、SMTP、MySQL、Redis 等服务。它不是版本漏洞扫描器，不做 CVE 匹配。

#### `dns` — 记录查询

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `DOMAIN` | 必填 | 目标域名 |

查询 A、AAAA、CNAME、MX、NS、TXT。使用 Go 标准库解析器，受手机当前 DNS 配置影响；如果系统 DNS 被运营商劫持，结果也会跟着偏。

```text
nezha > use dns
nezha (dns) > set DOMAIN example.com
nezha (dns) > run
```

#### `whois` — 注册信息

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `TARGET` | 必填 | 域名或 IP |
| `SERVER` | 空 | 留空自动发现权威 WHOIS 服务器 |
| `TIMEOUT` | `15s` | 连接与读取总超时 |
| `RAW` | `false` | 是否附加原始文本 |

走 TCP 43。部分注册局对查询频率有限制，连续查询同一目标可能被临时拒绝。

#### `subdomain` — 子域枚举

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `DOMAIN` | 必填 | 根域名 |
| `WORDLIST` | 空 | 自定义字典，每行一个前缀 |
| `THREADS` | `32` | DNS 解析并发数 |
| `CRT` | `true` | 是否查询 crt.sh 证书透明日志 |

内置约 225 个常见前缀（`www`、`api`、`admin`、`jenkins`、`grafana` 等），并检测泛解析通配符，避免把通配结果全算成命中。

```text
nezha > use subdomain
nezha (subdomain) > set DOMAIN example.com
nezha (subdomain) > set WORDLIST ~/storage/shared/words.txt
nezha (subdomain) > run
```

边界：只做 DNS 解析验证，不主动访问子域；crt.sh 不可达时会跳过并给出提示。

#### `lan` — 局域网存活发现

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `CIDR` | 空 | 留空自动推断本机 `/24` |
| `DISCOVER` | `true` | 是否执行活跃主机探测 |
| `PORTS` | `22,80,443,445,62078` | 存活判定端口 |
| `TIMEOUT` | `300ms` | 单次连接超时 |
| `WORKERS` | `128` | 并发主机数 |

它是 **TCP 探针式**发现，不是 ARP 扫描：向每个地址的若干端口发起连接，有响应就认为主机存活。优点是免 Root，缺点是对只开 UDP 或被防火墙全 drop 的主机会漏报。

### 1.2 Web 类

#### `web` — HTTP 安全审计

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `URL` | 必填 | 目标 URL，可省略 `http://` |
| `TIMEOUT` | `10s` | 单次请求超时 |
| `DEEP` | `true` | 是否检查标准文件与 OPTIONS 方法 |

检查项：

- CSP、HSTS、`X-Frame-Options`、`X-Content-Type-Options`、`Referrer-Policy`、`Permissions-Policy`；
- Cookie 的 `Secure`、`HttpOnly`、`SameSite`；
- `robots.txt`、`sitemap.xml`、`security.txt`；
- `OPTIONS` 返回的 `Allow` 方法；
- `Server` 与 `X-Powered-By` 的信息暴露提示。

只做只读请求，不发送 SQL 注入、XSS、命令注入载荷。

#### `tls` — 证书与协议检查

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `TARGET` | 必填 | 主机或 `https://` URL |
| `PORT` | `443` | URL 自带端口时优先 |
| `TIMEOUT` | `10s` | 连接与握手超时 |

输出 TLS 版本、密码套件、证书主题、签发者、有效期、SAN、信任链状态。自签名或过期证书会明确标出，不会静默当作可信。

#### `webdir` — 敏感路径探测

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `URL` | 必填 | 目标站点 |
| `CODES` | `200,204,301,302,307,308,401,403` | 视为命中的状态码 |
| `THREADS` | `24` | 并发请求数 |
| `TIMEOUT` | `5s` | 单次请求超时 |

内置字典覆盖管理后台、`.git`、`.env`、备份文件、Swagger、Actuator 等高频暴露面。它只看状态码与少量响应特征，不做目录递归爆破。

### 1.3 无线类

无线模块全部依赖 ESP 协处理器。没有板子时，`esp`、`wifi_scan`、`wifi_deauth`、`wifi_brute`、`wifi_clone` 会直接报串口错误，不会假装成功。

#### `esp` — 握手与能力探测

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | 空 | 留空自动探测唯一 USB 串口 |
| `SCAN` | `false` | 握手后是否执行一次扫描 |

这是所有无线操作前的自检：打开串口、执行 DTR/RTS 复位、重发 PING 直到收到 PONG，然后报告协议版本、是否支持 5GHz 以及周边 AP 数量。

#### `wifi_list` — 本机无线信息

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `ESP` | `false` | 为 `true` 时改走协处理器扫描 |
| `PORT` | 空 | ESP 模式下的串口 |

`ESP=false` 时读取本机网络接口与 `/proc/net/wireless`，属于被动信息；Android 对后者限制较多，读不到时会明确说明。

#### `wifi_scan` — 周边 AP 扫描

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | 空 | 串口设备 |
| `SORT` | `rssi` | `rssi` / `channel` / `ssid` |
| `MIN_RSSI` | `-100` | 低于该值过滤 |
| `HIDDEN` | `true` | 是否显示隐藏 SSID |

返回 SSID、BSSID、信道、RSSI。2.4GHz 板子看不到 5GHz/6GHz 网络；ESP32-C5 才能覆盖 5GHz。

#### `wifi_deauth` — deauth / disassoc 注入

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | 空 | 串口设备 |
| `BSSID` | 必填 | 目标 AP 的 BSSID |
| `CHANNEL` | `0` | `0` 表示先扫描自动定位 |
| `STATION` | 空 | 目标客户端 MAC；留空为广播 |
| `FRAME` | `both` | `deauth` / `disassoc` / `both` |
| `COUNT` | `32` | 注入帧总数，上限 10000 |
| `INTERVAL` | `50ms` | 帧间隔 |
| `REASON` | `7` | 802.11 Reason Code |

```text
nezha > use wifi_deauth
nezha (wifi_deauth) > set BSSID aa:bb:cc:dd:ee:ff
nezha (wifi_deauth) > set CHANNEL 6
nezha (wifi_deauth) > set FRAME both
nezha (wifi_deauth) > set COUNT 32
nezha (wifi_deauth) > run
# 授权确认处输入 yes
```

帧布局：完整构造 34 字节（radiotap 8 + MAC 头 24 + Reason 2）；注入前剥离 radiotap，固件实际收到“1 字节信道 + 26 字节纯 802.11 帧”。

边界：

- WPA3 与 6GHz 网络强制启用 PMF（802.11w），未认证的 deauth/disassoc 会被客户端丢弃。这是协议约束，不是注入失败。
- 广播帧影响该 AP 下所有客户端；定向帧需要正确的 `STATION`。
- 信道填错时帧发不到目标，表现为“命令成功但目标不断”。
- 高影响模块，`run` 后必须输入 `yes` 才会执行。

#### `wifi_brute` — 在线密码字典

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | 空 | 串口设备 |
| `SSID` | 必填 | 目标 SSID |
| `WORDLIST` | 必填 | 密码字典，每行一个 |
| `DELAY` | `200ms` | 两次尝试之间的额外延迟 |
| `MAX` | `0` | 最大尝试次数；`0` 为不限制 |
| `STOP_ON_SUCCESS` | `true` | 命中后立即停止 |

单次尝试在主机侧最多等待 15 秒（`FrameRetryTimeout`），实际关联通常 2-5 秒。因此它适合小规模、受控字典，不适合大字典高速喷洒。频繁失败可能触发 AP 的锁定或告警。

#### `wifi_clone` — 克隆 AP

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT` | 空 | 串口设备 |
| `ACTION` | `status` | `up` / `down` / `status` / `watch` |
| `SSID` | 空 | `up` / `watch` 时必填 |
| `PASSWORD` | 空 | 留空表示开放网络 |
| `CHANNEL` | `1` | 克隆 AP 信道 |
| `WATCH` | `0s` | 监控时长；`0` 表示直到 Ctrl+C |
| `DOWN_ON_EXIT` | `true` | 监控结束后是否关闭克隆 AP |

`up` 创建同名同密码 SoftAP，`status` 查询在线设备，`down` 关闭，`watch` 定时轮询在线设备。这是高影响操作，仅限书面授权范围。

### 1.4 系统类

#### `sysinfo`

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `TARGETS` | `1.1.1.1:443,8.8.8.8:53` | 出站连通性探测目标 |
| `TIMEOUT` | `3s` | 单目标连接超时 |

输出主机名、系统、架构、UID、Root 状态、发行版、内核、网络接口与出站连通性。Android 上部分字段来自 `/proc` 与 `/sys`，读不到时显示为空而不是编造。

#### `bt`

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `SYSFS` | `/sys/class/bluetooth` | 蓝牙 sysfs 根目录 |

只被动读取 HCI 适配器名称、地址与 sysfs 路径，不发起扫描、配对或连接。非 Root Termux 通常读不到该目录，这属于 Android 权限边界。

### 1.5 作者 Go 工具移植
这组模块是把作者工具链的**真实代码逻辑**移植进控制台，运行时不调用上游二进制：

| 模块 | 来源 | 作用 | 高影响 |
| --- | --- | --- | --- |
| `vecmap` | vecmap | 向量数据库只读指纹（Qdrant/Milvus/Weaviate/Chroma/Elasticsearch/OpenSearch/Typesense/Vespa/Redis）、集合枚举、CVE 版本关联与 ATT&CK 映射 | 否 |
| `payloads` | BlindSQL | 盲注 payload 字典（内置代表性子集 + 外部字典） | 否 |
| `mitre` | MITRERedTeam | BB01-BB25 战术与 27 条技术目录、执行器到原生模块的映射 | 否 |
| `cve` | CVE-Exploits | PoC/Exploit 库目录与内置模块索引 | 否 |
| `cve_2025_14847` | CVE-Exploits | MongoBleed：OP_COMPRESSED 内存泄露探测 + 版本结论表 | **是** |
| `cve_2025_4334` | CVE-Exploits | WordPress 注册接口 role=administrator 提权验证 | **是** |
| `cve_2025_66478` | CVE-Exploits | React2Shell（Next.js）RSC 反序列化检测 | **是** |
| `webfinger` | QianKunQuan | CMS/WAF/技术栈指纹识别 | 否 |

```text
nezha > use vecmap
nezha (vecmap) > set TARGET 10.0.0.5:6333
nezha (vecmap) > run

nezha > use mitre
nezha (mitre) > set TACTIC BB01
nezha (mitre) > run

nezha > use cve
nezha (cve) > set ID CVE-2025-14847
nezha (cve) > run
```

判定与移植边界：

- `vecmap` 保持上游“只读铁律”，只发 GET/HEAD/OPTIONS 与只读 POST（Milvus v2 集合列表）；gRPC 深度探测、记录提取与 SQLite 证据库未移植，Milvus 走 REST 接口。
- `payloads` 内置字典是上游 2465 行 payload.txt 的常用族代表性子集；完整字典从上游仓库复制到本地后用 `WORDLIST` 加载。
- `mitre` 目录与上游 catalog JSON 逐条一致；执行器映射只指向本控制台已有的原生模块，其余标注“人工”。
- 三个 CVE 模块的载荷构造与判定阈值与上游 PoC 一致；`cve_2025_4334` 会在目标真实创建账户，`run` 前必须输入 `yes`。
- 会话结束后执行 `report 文件名` 导出 Markdown 评估报告（QianKunQuan 报告能力移植）。

### 1.6 战场基础工具与脚本控制

| 模块/命令 | 作用 | 关键参数 |
| --- | --- | --- |
| `hash` | MD5/SHA1/SHA256 完整性校验，可选期望值比对；比对失败返回错误 | `INPUT` `ALGO` `EXPECT` |
| `encode` | base64/hex/URL 编解码 | `ACTION` `ALGO` `VALUE` |
| `random` | crypto/rand 口令令牌生成 | `LENGTH` `CHARSET` `COUNT` |
| `connect` | 一次性 TCP 原始交互，hex+文本双栏回显，替代 nc | `HOST` `PORT` `SEND` `HEX` `WAIT` |
| `http` | 原始 HTTP 请求构造与回显 | `URL` `METHOD` `HEADERS` `BODY` `BODYFILE` |
| `crunch` | 流式口令字典生成，单次上限 1000 万行 | `CHARSET` `MIN` `MAX` `OUTPUT` `LIMIT` |
| `repeat` | 周期重复执行命令，Ctrl+C 中断 | 次数 间隔 命令 |
| `watch` | 无限轮询执行命令，Ctrl+C 停止 | 间隔 命令 |
| `sleep` / `echo` / `source` | 脚本休眠 / 输出 / 执行脚本文件 | 时长 / 文本 / 路径 |
| `save` / `load` | 控制台状态导出与恢复（JSON，权限 0600） | 文件路径 |
| 行编辑 | 交互终端支持 ↑↓ 历史、←→ 光标、Ctrl+A/E/U/W/K，中文整字处理 | - |

可靠性设计：

- 模块内部 panic 由引擎恢复并转换为错误，控制台不会崩溃；
- `crunch` 与 `connect` 全程遵守上下文取消，Ctrl+C 立即停止且保留已写入内容；
- 脚本模式下模块失败会让进程以退出码 1 结束，`-c @文件` 可直接接入流水线；
- `random` 使用 crypto/rand 拒绝采样，避免取模偏差导致的口令可预测性。

```text
nezha > use connect
nezha (connect) > set HOST 192.168.1.1
nezha (connect) > set PORT 80
nezha (connect) > set SEND "GET / HTTP/1.0\r\n\r\n"
nezha (connect) > run

nezha > use crunch
nezha (crunch) > set CHARSET abc123
nezha (crunch) > set MIN 1
nezha (crunch) > set MAX 4
nezha (crunch) > set OUTPUT ~/dict.txt
nezha (crunch) > run

nezha > repeat 6 5s run     # 每 5 秒重复执行当前模块，共 6 次
nezha > watch 10s run       # 每 10 秒轮询直到 Ctrl+C
```

---

## 2. ESP 协处理器完整路径

### 2.1 为什么必须走协处理器

非 Root Android 应用没有 `CAP_NET_RAW`，不能：

- 创建 monitor 接口；
- 打开原始套接字；
- 注入 802.11 管理帧；
- 抓取空中数据包。

所以主动无线能力不能靠手机内置 WiFi 完成。ESP 方案把射频工作放到开发板上，手机只通过 USB 串口发送协议帧：

```text
Termux / Nezha  ──USB 串口──>  ESP8266 / ESP32  ──2.4/5GHz──>  目标 AP / 客户端
                115200 8N1          固件负责射频
```

开发板不需要连接任何 WiFi，也不需要开热点。deauth 是伪造帧，不是关联。

### 2.2 硬件选型

| 开发板 | 注入原语 | 频段 | 支持 |
| --- | --- | --- | --- |
| ESP8266（NodeMCU、Wemos D1 mini 等） | `wifi_send_pkt_freedom` | 2.4GHz（信道 1-14） | 支持 |
| ESP32 经典 / C2 / C3 / S2 / S3 | `esp_wifi_80211_tx` | 2.4GHz（信道 1-14） | 支持 |
| ESP32-C5 | `esp_wifi_80211_tx` | 2.4 + 5GHz（1-14 / 36-165） | 支持 |
| Arduino UNO + WiFi Shield（NINA/WINC） | 无开放注入 API | — | 不支持，固件编译期直接拒绝 |

其他要求：

- USB 串口芯片：CH340、CP2102 或板载 USB-JTAG；
- 必须是**数据线**，纯充电线没有 D+/D-；
- OTG 供电要够：ESP8266 射频瞬时电流可达 300mA，手机 OTG 口可能带不动，优先用带供电的 Hub 或低功耗 ESP32-C3；
- 固件源码：[wifisec/core/esp/esp.ino](https://github.com/ctkqiang/wifisec/blob/main/core/esp/esp.ino)，协议版本 v1。

### 2.3 烧录固件

推荐在电脑上烧录，再把板子插到手机；Android 上烧录需要串口权限，通常比电脑麻烦。

先把固件源码取到本地：

```bash
git clone https://github.com/ctkqiang/wifisec.git
cd wifisec
```

#### 方式一：arduino-cli（推荐）

```bash
# 一次性安装工具链与 ESP8266 板卡索引
brew install arduino-cli          # macOS；Linux/Windows 见官方安装文档
arduino-cli config init
arduino-cli config set board_manager.additional_urls \
  https://arduino.esp8266.com/stable/package_esp8266com_index.json
arduino-cli core update-index
arduino-cli core install esp8266:esp8266

# 确认端口
arduino-cli board list

# 编译：FQBN 必须与真实硬件一致
arduino-cli compile \
  --fqbn esp8266:esp8266:nodemcuv2:baud=115200,xtal=80,eesz=4M2M \
  --build-path /tmp/esp-build \
  core/esp/esp.ino

# 上传
arduino-cli upload \
  --fqbn esp8266:esp8266:nodemcuv2 \
  --input-dir /tmp/esp-build \
  -p /dev/cu.usbserial-XXXX \
  core/esp/esp.ino
```

FQBN 每一项都不是装饰：

| 配置 | 含义 | 选错的后果 |
| --- | --- | --- |
| `nodemcuv2` | NodeMCU 1.0（ESP-12E） | 板型携带晶振参数，选错会导致波特率整体偏移 |
| `baud=115200` | 上传波特率 | 460800/921600 在廉价 CH340 上线材容易擦写超时 |
| `xtal=80` | CPU 80MHz | 160MHz 会增加射频初始化电流浪涌 |
| `eesz=4M2M` | 4MB Flash，2MB SPIFFS | 与板子真实容量不符会出现烧录地址警告 |

ESP32 系列先执行 `arduino-cli core install esp32:esp32`，再用 `arduino-cli board listall | grep -i esp32` 查确切 FQBN。

#### 方式二：Arduino IDE

1. 打开 `core/esp/esp.ino`；
2. 开发板选择与实际型号一致（NodeMCU 选 `NodeMCU 1.0 (ESP-12E Module)`）；
3. `Upload Speed` 选 `115200`；
4. 选择串口并上传。

### 2.4 烧录排错

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `Timed out waiting for packet header` | 自动复位电路没把 GPIO0 拉低，没进下载模式 | 按住 `FLASH` → 点按 `RST` → 松开 `FLASH` → 立即上传 |
| `Running stub...` 之后擦写超时 | 高速 stub 在擦写阶段丢包，多见于供电/线材临界 | 降低波特率，或用 esptool `--no-stub` 直接走 ROM |
| 串口有数据但不是有效 PONG | 板型晶振选错，115200 实际跑成 74880 | 选对板型重新烧录；可用 74880 打开串口验证 |
| 烧录后 `/dev/cu.usbserial-*` 消失 | 射频初始化瞬时电流过大，板子掉电或 USB 口过流保护 | 直连电脑 USB，换短粗数据线，避免 Hub |
| 编译报内存溢出 | 板型/分区配置不对 | 按上表重新选择 FQBN；IRAM 91% 是 ESP8266 基线，不算溢出 |
| `no headers files (.h) found` | `Arduino/libraries` 下有结构不正确的目录 | 把误放目录移出 `libraries/` |

烧录成功的标志：板载 LED **快闪三下**，随后进入约 0.5 秒一次的心跳闪烁。没有心跳说明固件没跑起来。

### 2.5 串口识别

`PORT` 留空时，模块按以下模式自动探测：

```text
/dev/ttyUSB*        /dev/ttyACM*        /dev/ttyCH343USB*
/dev/ttyXRUSB*      /dev/ttyHS*         /dev/cu.usbserial*
/dev/cu.SLAB_USBtoUART*                 /dev/cu.wchusbserial*
```

只返回字符设备。发现多个候选时不会猜测，必须显式设置：

```text
nezha > use esp
nezha (esp) > set PORT /dev/ttyUSB0
nezha (esp) > set SCAN true
nezha (esp) > run
```

Linux/Termux 常见 `1A86:7523`（CH340）、`10C4:EA60`（CP2102）。macOS 常见 `/dev/cu.usbserial-XXXX`。

### 2.6 Termux 串口访问边界

ESP 路径不需要 Android 的 raw socket，但 Termux 仍然必须能**打开串口设备节点**：

```bash
ls -l /dev/ttyUSB* /dev/ttyACM*
```

三种情况：

1. **节点存在且可读写**：直接使用。
2. **没有节点**：检查 OTG 数据线、供电、串口芯片驱动。部分 Android 内核根本不创建 `ttyUSB` 节点。
3. **节点存在但 `Permission denied`**：当前 ROM/内核没有把该节点开放给 Termux 应用 UID。

当前实现直接用 termios 打开 `/dev/ttyUSB*`，**不经过 Android USB Host API，也不使用 `termux-usb` 的文件描述符传递**。因此：

- 如果你的设备只在 Android USB Host API 下暴露串口，本项目的 ESP 模块无法直接使用；
- 可行替代：使用已 Root 的设备、改用 Linux 主机，或等待后续实现 `termux-usb` fd 适配；
- 模块打不开串口时会明确报错，不会静默假装成功。

> 这不是“再装一个包”能解决的问题，而是 Android 权限模型与设备内核的边界。

另外，`make build-local` 在 macOS 上会使用非 Linux 串口桩，ESP 模块会明确报“当前平台不提供原生串口驱动”。ESP 功能必须使用 `make build` 生成的 Linux/ARM64 产物，或在 Linux 主机上运行。

### 2.7 验证顺序

先握手，再扫描，最后才执行主动操作：

```text
nezha > use esp
nezha (esp) > set SCAN true
nezha (esp) > run

nezha > use wifi_scan
nezha (wifi_scan) > set SORT rssi
nezha (wifi_scan) > set MIN_RSSI -80
nezha (wifi_scan) > run
```

握手日志应包含协议版本与频段能力。若一直收不到 PONG：

- 确认端口没有被 Arduino 串口监视器、`screen`、`minicom` 占用；
- 确认波特率是 115200；
- 确认板子 LED 有心跳；
- 确认固件是 wifisec 的 `core/esp/esp.ino`，不是别的 sketch。

### 2.8 协议速查

主机到 ESP：

```text
[0xA5][cmd][len_lo][len_hi][payload]
```

ESP 到主机：

```text
[0x5A][cmd][len_lo][len_hi][payload]
```

| 方向 | cmd | payload | 说明 |
| --- | --- | --- | --- |
| 主机→ESP | `0x00` | 无 | PING 握手 |
| 主机→ESP | `0x01` | 无 | 请求扫描 |
| 主机→ESP | `0x02` | 信道(1) + 802.11 帧 | 注入，帧不含 radiotap |
| 主机→ESP | `0x03` | SSID 长度 + SSID + 密码长度 + 密码 | 关联尝试 |
| 主机→ESP | `0x05` | 操作码(1) + 信道(1) + SSID 长度(1) + SSID + 密码长度(1) + 密码 | 克隆 AP |
| 主机→ESP | `0x06` | 无 | 查询克隆 AP 在线设备 |
| ESP→主机 | `0x00` | 协议版本(1) + 能力位图(1) | PONG |
| ESP→主机 | `0x01` | BSSID(6) + 信道(1) + RSSI(1) + SSID 长度(1) + SSID | 扫描条目 |
| ESP→主机 | `0x02` | 无 | 扫描结束 |
| ESP→主机 | `0x04` | 出错命令(1) + 错误码(1) | 错误 |

能力位图 bit0 表示支持 5GHz（当前仅 ESP32-C5）。旧固件只回 1 字节版本号时，主机按“仅 2.4GHz”处理。

设计要点：

- 打开串口先拉复位时序，避免芯片锁进 ROM 下载模式；
- 每次操作先握手，boot 期间命令会丢；
- 解析器逐字节丢弃噪声直到帧头 `0x5A`，残缺帧保留待拼齐；
- 注入不回 ACK，避免占用 115200 串口带宽；
- payload 上限 512 字节，超长固件直接拒绝。

### 2.9 无线排错

| 现象 | 可能原因 | 处理 |
| --- | --- | --- |
| `打开串口失败` | 端口不存在、被占用、权限不足 | `ls -l` 确认节点；关闭占用进程；检查 Termux 权限 |
| `复位开发板失败` | DTR/RTS 不被支持或线材问题 | 换数据线；确认板子支持自动复位 |
| `固件握手失败` | 波特率/晶振不对、固件没跑 | 重新烧录匹配板型的固件；检查 LED 心跳 |
| 扫描到 0 个 AP | 2.4GHz 板子扫 5GHz、天线/供电问题 | 换 2.4GHz 目标；靠近 AP；检查供电 |
| deauth 无效果 | PMF（WPA3/6GHz）、信道错误、目标太远 | 换 WPA2 目标；`CHANNEL=0` 自动定位；靠近目标 |
| 密码尝试全部超时 | 字典太大、AP 限速、信号弱 | 缩小字典；增加 `DELAY`；先确认 RSSI |
| 克隆 AP 起不来 | 信道非法、密码长度不符合 WPA2、固件忙 | 用 1-11 信道；密码留空或 8-63 字符；先 `ACTION=down` 再 `up` |

---

## 3. 非 Root Termux 能力边界

| 能力 | 非 Root Termux | 原因 |
| --- | --- | --- |
| TCP connect 端口扫描 | 可用 | 普通 socket，不需要特权 |
| 服务 Banner 抓取 | 可用 | 普通 TCP 连接 |
| DNS / WHOIS | 可用 | 标准库解析器与 TCP 43 |
| HTTP 安全头 / TLS 证书 | 可用 | 标准 HTTP/TLS 客户端 |
| 子域名枚举 | 可用 | DNS 查询 + 可选 crt.sh |
| 局域网 TCP 存活探测 | 可用 | 不依赖 ARP 原始套接字 |
| 本机接口 / 系统信息 | 可用（受系统限制） | 读取 `/sys`、`/proc` 与标准库 |
| 蓝牙适配器枚举 | 可用（受系统限制） | 读取 `/sys/class/bluetooth`，Android 常拒绝 |
| ESP 扫描 / 注入 / 关联 / 克隆 | 需 ESP 板 + 可打开的串口 | 射频在开发板上，宿主不需要 raw socket |
| 本机 WiFi monitor / 原生注入 | 不可用 | 需要 Root / `CAP_NET_RAW` |
| SYN 扫描 / masscan 风格 | 不可用 | 需要原始套接字 |
| UDP 扫描 | 未实现 | 当前只有 TCP connect |
| 原始抓包 / ARP 欺骗 | 不可用 | 需要 `AF_PACKET` / BPF / Npcap 与特权 |
| 蓝牙主动扫描 / 配对 | 不可用 | Android 蓝牙栈由系统服务管理 |
| 自动漏洞利用 | 不提供 | 没有 exploit runtime |

补充说明：

- **Android 10+ 对 `/proc/net/*` 的限制**会让部分网络信息读取失败；模块会显示为空或给出说明。
- **共享存储字典**需要先执行 `termux-setup-storage`，否则 `~/storage/shared/...` 不存在。
- **后台执行**可能被 Android 省电策略杀掉；长时间任务先执行 `termux-wake-lock`。
- **OTG 供电**是 ESP 路径最常见的“硬件故障”：板子能亮但射频一开就掉电，表现为串口设备消失或握手随机失败。

---

## 4. 可选外部工具对照

以下工具**不是本项目依赖**，也不会被原生模块自动调用。它们适合在你已经熟悉、且明确需要某个专用能力时，与 `nezha` 并行使用。下表按 2026-11 的 Termux 官方仓库与常见上游安装方式整理；仓库会变，安装前先 `pkg search <name>` 确认，找不到就走上游 Release 或源码编译。

| 外部工具 | 典型用途 | Termux 获取 | 原生替代 | 备注 |
| --- | --- | --- | --- | --- |
| `nmap` | 端口/服务/脚本扫描 | `pkg install nmap` | `portscan` `service` | SYN 扫描需 Root；`-sT` 可非 Root |
| `masscan` | 大规模高速扫描 | 源码编译 | 无 | 需要 libpcap 与原始套接字/Root |
| `netcat-openbsd` | 手工连端口、传数据 | `pkg install netcat-openbsd` | 无 | 调试用 |
| `dnsutils`（`dig`） | 指定 DNS 服务器查询 | `pkg install dnsutils` | `dns` | 原生模块不指定自定义 DNS |
| `whois` | 注册信息查询 | `pkg install whois` | `whois` | 原生已覆盖 |
| `subfinder` / `amass` | 被动子域枚举 | 上游 Release / Go 安装 | `subdomain` | 数据源更多，体积更大 |
| `httpx` | HTTP 存活与指纹 | 上游 Release / Go 安装 | `web` | 批量场景更强 |
| `nikto` | Web 服务器扫描 | 上游源码（Perl） | `web` | 会发送更多探测请求 |
| `ffuf` / `gobuster` | 目录/参数爆破 | 上游 Release / Go 安装 | `webdir` | 字典与递归能力更强 |
| `nuclei` | 模板化漏洞扫描 | 上游 Release / Go 安装 | 无 | 模板生态，非原生 |
| `sqlmap` | SQL 注入检测 | `pip install sqlmap` | 无 | 主动注入，需单独授权 |
| `commix` | 命令注入检测 | `pip install commix` | 无 | 主动注入，需单独授权 |
| `wpscan` | WordPress 专项 | `gem install wpscan`（需 Ruby） | 无 | 专项工具 |
| `aircrack-ng` | 无线审计套件 | 源码编译 | 无 | 需要 Root + monitor |
| `hcxdumptool` / `hcxtools` | PMKID/握手捕获 | 源码编译 | 无 | 需要 Root + monitor |
| `kismet` | 无线侦测 | 源码编译 | 无 | 需要 Root/特权 |
| `iw` | 无线接口配置 | `pkg install root-repo` 后 `pkg install iw` | `wifi_list` | 配置类操作，非扫描 |
| `bluez`（`hcitool`） | 蓝牙扫描 | 源码编译 | `bt` | Android 蓝牙栈下通常不可用 |
| `tcpdump` | 抓包 | `pkg install root-repo` 后 `pkg install tcpdump` | 无 | 需要 Root |
| `tshark` | pcap 分析 | `pkg install root-repo` 后 `pkg install tshark` | 无 | 体量大，分析用 |
| `openssl` | 手工 TLS 探测 | `pkg install openssl` | `tls` | 调试证书链方便 |
| `curl` / `jq` | HTTP 调试与 JSON 处理 | `pkg install curl jq` | 无 | 通用工具 |
| `bettercap` | MITM/网络攻击框架 | 上游 Release / Go 安装 | 无 | 需要 Root，高影响 |

说明：

- Termux 主仓库目前直接提供 `nmap`、`netcat-openbsd`、`dnsutils`、`whois`、`openssl`、`curl`、`jq`。
- `iw`、`tcpdump`、`tshark` 在 `root-repo`，先安装 `root-repo` 再装包。
- `nikto`、`aircrack-ng`、`kismet`、`bluez`、`masscan`、`hcxdumptool`、`hcxtools` 不在官方主仓库，需要上游源码或 Release。
- `sqlmap`、`commix` 需要 Python 环境；`wpscan` 需要 Ruby 环境。
- 不要照抄不存在的 `pkg install` 命令；以 `pkg search` 与上游文档为准。

使用原则：

1. **能用原生模块完成的，不要先装外部工具**。原生路径参数更少、输出更统一、授权闸门一致。
2. **需要外部工具时，明确它在你自己的终端里运行**，不是 `nezha` 替你运行。
3. **不要把外部工具的输出直接当成 `nezha` 的结果**；两者没有数据打通。
4. **主动工具（sqlmap、nuclei、bettercap、aircrack-ng）必须单独确认授权范围**，不要因为 `nezha` 有授权闸门就默认外部工具也受控。

---

## 5. 作者 Go 工具集成状态

这张表是当前代码的真实状态。未集成的部分不会出现在 `show modules` 里。

| 项目 | 原始能力 | 在本项目中的落地 | 状态 |
| --- | --- | --- | --- |
| [wifisec](https://github.com/ctkqiang/wifisec) | ESP 协处理器无线测试：list/serial/deauth/jam/brute/clone/devices/scan_ports/sniff/bind/pmkid/ids/heatmap | `internal/wireless/esp` 串口协议、握手、注入、关联、克隆；`internal/wireless/ieee80211` 帧构造；6 个无线模块 | **核心路径已原生集成** |
| [SanTaiZi](https://github.com/ctkqiang/SanTaiZi) | 模块化控制台、注册表、加载器、SDK、`modules/bin` | `internal/core`、`internal/structure`、`internal/model`；`--info` / `--execute` 外部模块适配 | **架构与外部协议已集成** |
| [vecmap](https://github.com/ctkqiang/vecmap) | 向量数据库指纹、只读探测、集合枚举、CVE 关联、ATT&CK 报告 | `pkg/vecmap` 后端 + `vecmap` 模块；gRPC 深度探测、记录提取与 SQLite 证据库未移植 | **已原生集成（只读核心）** |
| [BlindSQL](https://github.com/ctkqiang/BlindSQL) | 盲注 payload 加载器与 2465 行字典 | `payloads` 模块：内置代表性子集、关键词过滤、外部字典加载 | **已原生集成（字典库）** |
| [MITRERedTeam](https://github.com/ctkqiang/MITRERedTeam) | BB01-BB25 战术、27 条技术、目录驱动、证据链 | `mitre` 模块：目录与执行器→原生模块映射；LLM 辅助与通知系统未移植 | **已原生集成（目录与映射）** |
| [CVE-Exploits](https://github.com/ctkqiang/CVE-Exploits) | CVE PoC/Exploit 集合 | `cve` 库目录 + 三个 Go PoC 原生移植（MongoBleed / WordPress 提权 / React2Shell 检测）；非 Go PoC 保留在仓库目录 | **部分原生集成（Go PoC + 目录）** |
| [QianKunQuan](https://github.com/ctkqiang/QianKunQuan) | 红队侦察、CVE/CNVD 索引、攻击路径、报告 | `webfinger` 模块 + `report` 命令；侦察模块覆盖部分；CVE 库与攻击路径生成未移植 | **部分原生集成（指纹 + 报告）** |
| [NezhaSec](https://github.com/ctkqiang/NezhaSec) | DeepSeek 编排、外部工具执行器、TUI | 未集成；本项目不引入 LLM 自动编排，也不默认调用外部工具 | **设计参考** |

### 5.1 wifisec 的逐项对照

| wifisec 命令 | 本项目对应 | 状态 |
| --- | --- | --- |
| `list` | `wifi_list`（`ESP=true` 时走协处理器） | 部分：本机被动信息 + ESP 扫描 |
| `serial` | `esp` 的自动探测；`Ports()` 枚举 | 部分：不做 VID:PID/产品名/序列号展示 |
| `deauth` | `wifi_deauth` | 已移植核心：广播/定向、deauth/disassoc、信道定位 |
| `jam` | 无 | 未移植：全频段轮扫 + 双帧连续干扰 |
| `brute` | `wifi_brute` | 已移植串口路径：字典、延迟、上限、命中即停 |
| `clone` | `wifi_clone` | 已移植：up/down/status/watch |
| `devices` | `lan` | 部分：TCP 存活探测，不做 ARP 表/主机名/设备角色 |
| `scan_ports` | `portscan` / `service` | 已覆盖：TCP connect + banner |
| `sniff` | 无 | 未移植：需要 `AF_PACKET`/BPF/Npcap 与特权 |
| `bind` / `shell` | 无 | 不移植：远程 shell/横向移动超出本项目边界 |
| `get_packet` | 无 | 未移植：需要原始抓包 |
| `pmkid` | 无 | 未移植：需要 EAPOL/PMKID 解析与主动帧交互 |
| `extract` | 无 | 未移植：pcap 离线分析 |
| `ids` | 无 | 未移植：帧级监测需特权 |
| `heatmap` | 无 | 未移植：TUI 采样与插值 |

### 5.2 为什么不做某些集成

- **不移植自动利用运行时**：三个 Go PoC 已原生移植并按授权闸门执行；其余非 Go PoC 保留在 CVE-Exploits 仓库目录，避免把多语言脚本硬塞进单二进制。
- **不移植远程 shell/横向移动**：这会改变工具性质，也超出“非 Root Termux 安全评估”的边界。
- **不引入 LLM 编排**：外部模型无法替代授权判断，且会把网络请求与工具调用变成不可预测的链路。
- **不内置 CVE/CNVD 全量库**：`vecmap` 内置的是带官方来源链接的向量库 CVE 种子库；全量 CVE 数据时效与来源责任重，需要时按外部模块显式接入。

---

## 6. 外部模块协议（可选）

如果你确实需要把独立二进制接进控制台，使用 SanTaiZi 兼容协议。它是**唯一**会触发 `os/exec` 的路径。

### 6.1 目录与权限

```text
modules/bin/
└── mytool        # 必须可执行
```

- 目录不存在时不报错，控制台照常启动。
- 只扫描普通文件；目录与不可执行文件跳过。
- 单个模块 `--info` 失败只产生警告，不影响其他模块。
- 目录路径相对于**当前工作目录**；在仓库根目录启动时才是 `./modules/bin`。
- 二进制必须是 **Termux / Linux / ARM64** 可执行文件；在 macOS 或 Windows 上编译的模块不能直接在手机上运行。

### 6.2 `--info` 输出

```text
name:mytool
description:示例外部模块
cnvd:CNVD-2024-0001
cve:CVE-2024-0001
option:TARGET:string:true:
option:MODE:string:false:fast
```

字段：

| 字段 | 说明 |
| --- | --- |
| `name` | 模块名；缺失时回退为文件名 |
| `description` | 描述；首行作为摘要 |
| `cnvd` / `cve` | 可选引用，展示在模块卡片 |
| `option:名称:类型:是否必填:默认值` | 与 SanTaiZi SDK 一致，可重复多行；类型仅用于展示 |

读取超时 5 秒。没有任何有效字段时该模块被跳过。

### 6.3 `--execute` 调用

```bash
mytool --execute MODE=fast TARGET=example.com
```

规则：

- 参数按名称排序，格式为 `KEY=VALUE`；
- 空值不传递；
- 必填参数由控制台在运行前校验；
- 标准输出与标准错误直接写入控制台；
- Ctrl+C 会取消上下文，子进程收到终止信号；
- 外部模块的 `Impact` 固定非空，因此 `run` 一定要求输入 `yes`。

### 6.4 示例：最小 shell 模块

```bash
#!/data/data/com.termux/files/usr/bin/sh
case "$1" in
  --info)
    echo "name:hello"
    echo "description:最小外部模块示例"
    echo "option:TARGET:string:true:"
    ;;
  --execute)
    shift
    for kv in "$@"; do
      case "$kv" in
        TARGET=*) echo "目标: ${kv#TARGET=}" ;;
      esac
    done
    ;;
  *)
    echo "用法: $0 --info | --execute KEY=VALUE" >&2
    exit 2
    ;;
esac
```

```bash
chmod +x modules/bin/hello
./bin/nezha -c "show modules; use hello; set TARGET example.com; run"
```

### 6.5 安全边界

- 只放你信任的本地二进制；外部模块拥有与 `nezha` 相同的用户权限。
- 外部模块不受原生模块的代码审计覆盖，行为由你自己负责。
- 不要把来源不明的 Release 直接丢进 `modules/bin`。
- 外部模块的 `--info` 输出是数据，不是指令；控制台不会执行其中的内容。

---

## 7. 构建、测试与验证

### 7.1 本机开发

```bash
gofmt -w cmd internal modules pkg test
go vet ./...
go test ./test/...
go test -race ./test/...
make build-local
./bin/nezha-local -version
```

### 7.2 Termux / ARM64 静态产物

```bash
make build
file bin/nezha
```

`make build` 等价于：

```bash
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build \
  -trimpath -ldflags="-s -w -extldflags '-static'" \
  -o bin/nezha ./cmd/nezha
```

`file bin/nezha` 应显示 `ELF 64-bit LSB executable, ARM aarch64`，且为静态链接。在 macOS/x86 Linux 上交叉编译出的产物需要复制到 Termux 运行。

### 7.3 复制到手机

```bash
# 在电脑上：先推到共享存储
adb push bin/nezha /sdcard/Download/nezha

# 在 Termux 中：先执行一次 termux-setup-storage
mkdir -p ~/bin
cp ~/storage/downloads/nezha ~/bin/nezha
chmod +x ~/bin/nezha
~/bin/nezha -version
```

Termux 不能直接从 `/sdcard` 执行二进制（挂载带 `noexec`），必须先复制到 `$HOME`。如果没有 `adb`，也可以通过 `scp`、共享存储或 Termux 的 `curl` 下载。

### 7.4 冒烟检查

```bash
./bin/nezha -l
./bin/nezha -c "show categories"
./bin/nezha -c "use dns; set DOMAIN example.com; run"
./bin/nezha -c "use sysinfo; run"
./bin/nezha -c "use mitre; run"
./bin/nezha -c "use payloads; set QUERY sleep; run"
./bin/nezha -c "use cve; run"
./bin/nezha -c "use webfinger; set URL https://example.com; run"
./bin/nezha -c "use hash; set INPUT abc; set ALGO sha256; run"
./bin/nezha -c "use random; set CHARSET hex; set COUNT 3; run"
./bin/nezha -c "use dns; set DOMAIN example.com; run; report smoke.md"
```

ESP 相关检查需要真实硬件：

```bash
./bin/nezha -c "use esp; set SCAN true; run"
```

---

## 8. 常见问题速查

| 问题 | 排查 |
| --- | --- |
| `exec format error` | 产物架构不对；确认是 `linux/arm64`，不是 `darwin/arm64` |
| `permission denied` 运行二进制 | `chmod +x`；Termux 内不能执行 `/sdcard` 上的文件，先复制到 `$HOME` |
| 端口扫描全是超时 | 目标不在线、防火墙 drop、手机网络限制；先扫网关或 `1.1.1.1:443` |
| DNS 查询失败 | 手机 DNS 不可用或被劫持；换网络，或用 `dig @1.1.1.1` 对比 |
| TLS 报证书错误 | 目标自签名/过期/域名不匹配；`tls` 会如实报告，不代表模块故障 |
| `web` 请求失败 | 目标只允许特定 Host/UA、需要代理、或 HTTP/2 强制；先用 `curl -v` 对比 |
| 子域枚举很慢 | 降低 `THREADS`，关闭 `CRT`，或换更小字典 |
| 串口打不开 | 见 §2.6；重点检查节点、权限、占用、数据线 |
| 握手一直失败 | 见 §2.4 与 §2.9；重点检查板型晶振、波特率、固件、LED 心跳 |
| deauth 无效 | 见 §2.9；重点检查 PMF、信道、距离 |
| 外部模块不出现 | 确认可执行、`--info` 5 秒内返回、至少有 `name` 或 `option` 行；用 `-debug` 看警告 |
| 控制台颜色错乱 | 管道输出会自动关色；也可 `-no-color` |

---

## 9. 授权与法律边界

本项目仅用于**已获得明确授权的安全评估、资产盘点与防御验证**。

严禁用于：

- 未经授权的网络扫描、入侵或干扰；
- 对他人 WiFi、蓝牙设备、主机或 Web 系统进行未授权测试；
- 窃取数据、绕过访问控制、破坏系统或持久化控制；
- 对公共网络、第三方设备或任何不属于你的资产执行 deauth、克隆 AP、密码尝试等主动操作。

`wifi_deauth`、`wifi_brute`、`wifi_clone` 会中断无线服务、尝试关联目标 AP 或创建伪造接入点，可能造成服务中断、账户锁定或告警。使用前必须确认目标属于你或已获得书面授权，并遵守当地法律法规。

外部工具（`sqlmap`、`nuclei`、`aircrack-ng`、`bettercap` 等）不受本项目的授权闸门控制；它们的授权责任由使用者自行承担。

作者不对任何滥用行为负责。

---

## 10. 相关文档

- [项目 README](../README.md)：控制台命令、模块总览、构建与测试。
- [wifisec](https://github.com/ctkqiang/wifisec)：ESP 固件、协议、无线能力上游。
- [wifisec 无线文档](https://github.com/ctkqiang/wifisec/tree/main/docs/feature)：deauth、brute、clone、serial 的详细原理与排错。
- [SanTaiZi](https://github.com/ctkqiang/SanTaiZi)：模块化控制台与外部模块 SDK 上游。
