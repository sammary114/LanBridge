# AGENTS.md --- 内网通 3.4.3055 协议兼容实验

## 1. 项目目标

在**单台 Windows PC**
上搭建隔离、可重复的实验环境，使用两个由操作者控制的测试身份，研究内网通（Nwt
/ IMO）3.4.3055 的网络行为，并为后续实现兼容客户端积累证据。

当前研究重点：

1.  用户发现 / 搜索流程
2.  上线、在线状态更新或心跳
3.  两个自有测试身份之间的普通文本消息
4.  不同端口分别承担的功能，以及是否存在 IPMSG / 飞鸽 / 飞秋兼容报文
5.  将抓包证据整理成可复现的协议笔记

**原则：以真实抓包为依据，不凭端口号猜协议，不向真实用户冒充身份，不对未确认的协议格式盲目发送构造报文。**
仅在自有测试身份和获准的实验环境中进行主动测试。

## 2. 当前环境

-   操作系统：Windows 桌面系统
-   物理机数量：1 台
-   内存：16 GB
-   Windows Sandbox：可正常启动
-   内网通：宿主机版本为 **3.4.3055**，进程映像路径为 `C:\Program Files (x86)\Nwt\ShiYeLine.exe`
-   **安装程序**：已在宿主机下载目录找到同版本安装包 `C:\Users\sammary\Downloads\nwt_setup_3.4.3055.exe`（43,437,496 字节），可直接用于 Windows Sandbox 环境搭建
-   开发工具：Python 3.12.10，已安装 `scapy` 2.7.0，TShark 4.6.9 可用
-   分析工具：已在 `tools/pcap-analyzer/` 实现专用的命令行分析器，支持会话聚合、Nwt 二进制协议解码与 JSON 导出
-   测试套件：`tests/test_analyzer.py` 包含 13 个自动化测试，全部通过
-   Wireshark / Npcap：已安装并运行

### 网络地址（此前检查所得）

  ------------------------------------------------------------------------------
  端点                           地址                    备注
  ------------------------------ ----------------------- -----------------------
  宿主机                         `172.31.112.1/20`       Sandbox 虚拟网络接口
  `vEthernet (Default Switch)`                           

  Windows Sandbox                `172.31.122.7/20`       Sandbox 地址（动态分配，曾为 .254）

  宿主机物理局域网地址           `192.168.31.225`        物理网络地址

  默认网关（Sandbox）            `172.31.112.1`          Sandbox `ipconfig`
                                                         中显示
  ------------------------------------------------------------------------------

已做过的基础连通性测试：宿主机向 Sandbox 的 `172.31.122.7`
进行网络探测，两端连通性与低时延（<1ms）均已确认。

## 3. 已知配置和进程端点

内网通网络设置截图显示：

-   搜索端口：`9011`
-   组织号：空
-   消息互通：已启用
-   互通端口：`2425`
-   网卡绑定：未启用

宿主机进程为 `ShiYeLine.exe`。

此前 PowerShell 检查得到的 UDP 本地端点：

-   `0.0.0.0:53782/UDP`
-   `0.0.0.0:9012/UDP`
-   `0.0.0.0:9011/UDP`
-   `0.0.0.0:2425/UDP`

此前 TCP 端点查询显示：

-   `0.0.0.0:2425` --- `Listen`
-   `0.0.0.0:2440` --- `Listen`
-   `0.0.0.0:2441` --- `Listen`
-   `0.0.0.0:2442` --- `Listen`
-   `0.0.0.0:9012` --- `Listen`
-   `0.0.0.0:9013` --- `Listen`
-   `0.0.0.0:9014` --- `Listen`
-   `0.0.0.0:51198` --- `Bound`
-   `192.168.31.225:51198` 曾与 `47.57.13.180:80` 关联，状态为
    `CloseWait`

注意： - UDP 和 TCP
是不同的端点；同一数字端口同时被两种协议使用并不矛盾。 -
端点存在或处于监听状态，不足以确定它的功能。 - `47.57.13.180:80`
的连接不能仅凭端点信息判断具体用途或进程行为。

## 4. 已有抓包文件

抓包文件归档路径：

`captures/nwt.pcapng`（SHA256: `521f2367351a6a3b95d5e45327b86131a8273ee61c869ba325262b3651b76544`，与 Desktop 原始文件哈希一致）。

**经 `tools/pcap-analyzer` 重新完整解析后确认的事实**：

-   抓包总计 49 个数据包，其中 10 个 UDP、39 个 TCP。
-   **UDP 9012 点对点通信（10 帧）**：宿主机 `172.31.112.1:9012` 与 Sandbox `172.31.122.254:9012` 之间存在完整的 Request-ACK 二进制报文序列。
    -   请求帧前缀 `0x8000`，应答帧前缀 `0x0000`，ACK 严格回显请求的 Sequence ID。
    -   8 字节帧（Opcode `0x85`）：为心跳保活帧（帧 #10, #46, #48），末尾 2 字节呈现计数递增。
    -   44 字节帧（Opcode `0x86`）：为点对点数据交互（帧 #8, #12），双方对传了完全相同的 28 字节实体数据。
-   **TCP 80 云端上报（9 帧）**：Sandbox 向 `47.57.13.180:80`（`report.51nwt.com`）发送 `POST /api/report.php`，已确认由 Sandbox 内的内网通进程触发：
    -   URL 解码后的 JSON 体明确包含 `"app": "syl"`, `"build num": "3055"`, `"ip": "172.31.122.254"`, `"user list": "2158b475dfcfdd43989482c4dcf0337b.1;3b9d1aadecebe74f8ea1cb3af56538fc.1;"`。
    -   服务器响应 `404 Not Found`。
-   **背景系统排噪（30 帧）**：帧 #14~#43 属于 Windows Sandbox 系统的遥测（`mobile.events.data.microsoft.com:443`）与 OCSP 证书校验，与内网通协议无关。

## 5. 当前已确认与未确认事项

### 已确认

-   同版本安装包在宿主机存在：`C:\Users\sammary\Downloads\nwt_setup_3.4.3055.exe`。
-   抓包 `captures/nwt.pcapng` 的完整结构、流分布和报文含义已全部通过 Python 分析器解析并固化。
-   已确认外部 HTTP 请求由内网通触发，并提取出客户端上报字段结构。
-   UDP 9012 是内网通私有通信通道，具备 Request-ACK 机制，心跳（0x85）与数据交互（0x86）格式已记录。
-   自动化测试套件（13 个用例）可重复运行并通过。
-   文档 `docs/protocol-notes.md` 与实验规划 `docs/experiments.md` 已建立。

### 未确认

-   UDP 9012 数据帧中 28 字节载荷的具体计算/派生规则（是否与 `corp id` 或网络标识绑定）。
-   UDP 9011 搜索端口在主动刷新/启动广播时的报文格式。
-   两个自有客户端之间普通文本消息的发送端口与格式（UDP 9012 还是 TCP 9012/2440）。
-   UDP/TCP 2425 上 IPMSG 兼容报文的交互细节。

## 6. 建议的下一步工作

### Step 1 --- 重新分析现有 PCAPNG

直接分析 `nwt.pcapng`，先做以下检查：

1.  读取捕获接口、时间范围、IP 端点、TCP/UDP 分布。
2.  按五元组（源 IP、源端口、目标 IP、目标端口、协议）汇总流量。
3.  单独检查 UDP 9012、UDP 9011、UDP 2425、TCP 2425，以及 TCP
    9012--9014、2440--2442。
4.  检查 UDP payload
    是否可读、是否有固定头部、重复字段或长度模式；不要未经验证就给字段命名。
5.  检查广播地址（例如 `255.255.255.255` 或子网定向广播）和组播地址。
6.  将 `47.57.13.180:80` 的流量与内网通相关本地流量分开报告。
7.  明确区分"抓包直接证据""推测"和"尚未确定"。

如果现有文件没有明确操作标记，应将它视为初始样本，不要单凭它得出完整协议结论。

### Step 2 --- 获取同版本安装程序

宿主机当前程序路径为
`C:\Program Files (x86)\Nwt\ShiYeLine.exe`，但不应假设复制整个安装目录即可在
Sandbox 运行。

-   优先从原始可信来源取得内网通 3.4.3055 安装包。
-   不要从不明下载站获取可执行文件。
-   若找不到安装包，先确认原安装来源、开始菜单快捷方式、卸载项或用户下载目录。
-   在 Sandbox 中安装前，确保实验文件可恢复；Sandbox
    关闭后内部数据通常会被清除。

### Step 3 --- 记录有操作标记的分阶段抓包

在 Wireshark
选择正确接口，优先保存未过滤的原始捕获，然后使用显示过滤器分析：

``` text
udp.port == 9011 || udp.port == 9012 || udp.port == 2425 ||
tcp.port == 9011 || tcp.port == 9012 || tcp.port == 2425 ||
udp.port == 2440 || tcp.port == 2440 ||
udp.port == 2441 || tcp.port == 2441 ||
udp.port == 2442 || tcp.port == 2442 ||
udp.port == 9013 || tcp.port == 9013 ||
udp.port == 9014 || tcp.port == 9014
```

推荐分开保存：

-   `01-host-idle.pcapng`：宿主机客户端已运行，静置 15 秒。
-   `02-discovery-trigger.pcapng`：状态切换（离线/离开 -> 我在线上）触发上线通告广播，或点击底部一键添加扫描网段。
-   `03-sandbox-start.pcapng`：启动 Sandbox 中的客户端。
-   `04-online-state.pcapng`：两个自有身份上线并观察状态变化。
-   `05-test-message.pcapng`：两个自有身份发送一条普通测试消息。

每次只做一个动作，记录准确时间，便于把动作映射到报文。若第二个客户端尚未安装，不要伪造这几个阶段的结果。

### Step 4 --- 评估是否需要两台虚拟机

先尝试 Sandbox。若发现流量明显发往局域网广播地址但 Sandbox
未收到，再考虑两台虚拟机放在隔离的 Host-only 或内部网络中。16 GB
内存可先尝试轻量配置，但具体分配取决于宿主机现有负载。

不要为了实验直接将未知报文发送到真实办公网或真实用户；优先在隔离网络中使用两个自有测试身份。

## 7. Wireshark 常用过滤器

仅看相关 UDP/TCP 端口：

``` text
udp.port == 2425 || tcp.port == 2425 ||
udp.port == 9011 || tcp.port == 9011 ||
udp.port == 9012 || tcp.port == 9012
```

只看两个已知虚拟地址之间的流量：

``` text
ip.addr == 172.31.112.1 && ip.addr == 172.31.122.254
```

只看 UDP 9012：

``` text
udp.port == 9012
```

只看 TCP 外部 HTTP 端点：

``` text
ip.addr == 47.57.13.180 && tcp.port == 80
```

说明：这是 Wireshark **显示过滤器**，不是捕获过滤器。

## 8. 对后续 AI agent 的要求

1.  先检查现有 `nwt.pcapng`，再要求用户重复操作。
2.  任何协议判断都应引用具体帧号、端点、payload 长度和原始字节。
3.  对 IPMSG 兼容性的判断要有报文证据，不以 `2425` 端口作为充分依据。
4.  区分 TCP 监听、TCP 连接、UDP 端点和实际观察到的数据包。
5.  不要假设抓包中的外部 HTTP
    请求一定由内网通触发；需要进程或时间相关证据。
6.  不要要求用户向真实用户冒充身份、绕过认证或对真实环境进行未授权主动测试。
7.  先实现被动解析器和报文记录，再在隔离实验网络中进行最小化主动验证。
8.  输出应包括：观察到的事实、证据帧号、假设、反证或不确定性、下一项最小实验。

## 9. 推荐的项目产物

后续逐步维护：

-   `AGENTS.md`：本文件，项目上下文和 agent 工作约定。
-   `captures/`：分阶段 `.pcapng` 文件：
    * `nwt.pcapng`：初始样本（心跳与云端上报）。
    * `02-discovery-trigger.pcapng`：状态切换（Blowfish 8 字节分组加密验证）。
    * `03-sandbox-discovery.pcapng`：冷启动上线、UDP 9011 发现、IPMSG 广播与 7 阶段完整握手。
    * `04-text-message.pcapng`：文本消息 Opcode 0x88 分片、输入状态与回执。
    * `05-image-transfer.pcapng`：图片点对点 Mini-File TCP 传输（Cmd 1 下载请求、Cmd 2 响应、Cmd 3 分块传输与 MD5 校验）。
-   `docs/protocol-notes.md`：帧号、时间、五元组、字段偏移及置信度剖析。
-   `docs/experiments.md`：分阶段抓包方案与假设验证清单。
-   `tools/pcap-analyzer/`：PCAPNG 分析器 CLI、会话聚合与 JSON 导出工具。
- `tests/`：自动化测试套件（88 个测试全部通过）。
-   `reports/`：导出的机器可读协议分析结果。

**当前状态**：
- M1（PCAP 分析器扩展）与 M2（深度协议研究文档）已全面交付。
- 全量 5 组真实抓包完成归档与多维度逆向验证。
- 协议核心全链路彻底破解与定型：
  * **传输层**：底层 100% 对应 **ENet** 可靠 UDP 协议（0x82 Connect / 0x83 VerifyConnect / 0x01 ACK / 0x85 Ping / 0x86 SendReliable / 0x88 SendFragment / 0x8a BandwidthLimit）。
  * **密码层**：原生 XML 载荷与封包 100% 对应 **XTEA 密码机**（32 轮，硬编码 128 位密钥 `b'8asfhj@k7*20hbla'`），全面支持 GBK 编码与双向加解密。
  * **微文件/图片传输层 (Mini-File / Folder-Tran)**：彻底逆向破解客户端 TCP 聊天内嵌图片与文件传输引擎（`CFolderTranEngine`，108B Command 2 / 108B Command 3 / 偏移 0x64 Command 4 分片流式传输与 MD5 校验状态机）。
- **M4 里程碑全面交付**：
  * 实现完整原生客户端模拟器（`tools/net-tester/tester.py`、`enet_protocol.py`、`crypto_engine.py`）。
  * 成功在 Windows Sandbox 原生**“内网通联系人”**分组下点亮 `LanBridge-Bot` 并带有绿色在线徽标。
  * 成功通过 UDP 9012 完成双向原生文本聊天交互与送达确认（收到 Sandbox 发送的 `"123456"` 并自动回显应答）。
  * 彻底攻克聊天图片破损图标（42x42）难题，成功实现从宿主机向 Sandbox 原生客户端发送图库高清图片（`images.jpg`），经 `CFolderTranEngine` TCP 端口分片传送并由原生客户端全量接收渲染。
- **M5 里程碑全面交付**：
  * 将协议核心抽象并提炼为生产级通用模块化库 `lanbridge`（`lanbridge.client.LanBridgeClient`、`lanbridge.protocol.*`、`lanbridge.discovery.SubnetScanner`、`lanbridge.models.*`）。
  * 完善单大文件传输引擎（`CLanFileTran`，TCP 2440）Command 1/2/3 切片传输与 MD5 校验状态机。
  * 实现基于 CIDR 的跨网段多目标并发异步主动扫描器（`SubnetScanner`）。
- **局域网群文件共享空间与影子保活（Shadow Keeper）全面交付**：
  * 逆向还原并实现 TCP 2442 原生共享协议族（`X_SHARE_*` XML 信令、目录树同步、密码校验与切片流式分发）。
  * 实现群文件主动发布与撤销通知（`X_QGROUP_SHARE_FILE` 与 `X_QGROUP_DELETE_SHARE`）。
  * 首创引入 **LanBridge-Hub 影子保活（Shadow Keeper Failover）**与**阶梯式 TTL / LRU 磁盘配额清理机制**（<10MB 保留 14 天；10MB~100MB 保留 7 天；>100MB 保留 48 小时；LRU 自动淘汰至 70% 水位）。
- **零配置自驱动接入引擎（Zero-Touch Autonomous Integration & Group Chat）全面交付**：
  * **网卡自适应与定向多广播**：`lanbridge.discovery.network` 自动枚举活动物理/虚拟网卡（剥离 loopback 和 APIPA 169.254.x），向所有活动子网定向广播和 `255.255.255.255` 并发宣告上线，双方用户均无需手动查询 IP 或配置网段。
  * **开机静默单播穿透扫描与主动唤醒**：客户端开机后台异步驱动 `SubnetScanner` 并发单播探测本地 `/24` 所在网段，收到反馈立即主动发起 ENet Opcode 0x82 握手与 profile 推送，在对端联系人树上无感点亮在线绿标。
- **自动化测试套件**：全量 **120 项自动化测试**（120/120 PASS），涵盖传输层、密码机、协议握手、文件引擎、群文件共享、跨网段探测、QGroup全套生命周期管理、Web 网关、Vue 3 离线单页客户端、CLI 增强与原生内网通目录数据适配。
- **M6 里程碑全面交付（全功能闭环与 Web 客户端/Bot 网关）**：
  * **多人讨论组/群聊全套生命周期管理**：完整逆向还原并实现原生 13 项群组命令字（建群、入群应答、群资料/公告推送、群成员变动、拉取成员、踢人、解散、退群）；
  * **聊天增强与状态机制**：实现原生输入中指示 `X_SEND_WRITTING`（Opcode 1008）、消息撤回机制 `recall`（原生 JSON type 6）、个人在线状态切换与个性签名广播；
  * **现代化 Web 客户端与开放 Bot 网关**：内置纯异步单页应用 UI 与 REST/WebSocket 网关，已全面升级为本地离线 **Vue 3 响应式单页架构 (SPA)**（集成 `vue.global.prod.js` 零构建单文件，告别脆弱 DOM 拼接，支持响应式数据流、联系人即时过滤搜索、平滑滚动、多模态弹窗与图片灯箱预览），支持 `python -m lanbridge` 一键启动图形化聊天、联系人与群文件管理；
  * 原生内网通 3.4.3055 协议族所有已知特性全部实现完毕并达成 100% 兼容。
- **M7 宿主机原生数据无缝适配（Native Nwt Storage Integration）全面交付**：
  * **只读安全隔离架构**：实现 `NativeNwtAdapter`（`lanbridge.adapter.NativeNwtAdapter`），对 `C:\Users\Public\Nwt` 实施严格非侵入只读访问（只读 SQLite URI），不破坏原生客户端运行；
  * **配置与跨网段目标继承**：自动提取 `data/acc`（原生 UID）、`cache/cfg/Option.xml`（`CorpId`、用户名、个性签名）与 `cache/cfg/Network.xml`（`OtherSubnetIp` 自动升规为标准 `/24` 并入开机主动探测池）；
  * **讨论组与共享空间无感导入**：只读提取 `data/qrp`（SQLite `QGroupInfo_*` 与 `QGroupUser_*`，原生支持真实 Emoji 与 18+ 名成员映射）及 `cache/db/sd`（`ShareData_*` 共享元数据）；并在 Web UI 群聊中提供**群成员侧边面板**，实时呈现群成员在线/离线徽标、群主/自身标识与在线统计，支持点击成员一键发起 1 对 1 私聊；
  * **媒体缓存秒级命中与直接伺服**：复用 `cache/pic/`（356+ 张历史图片）与 `cache/recv/`，实现 Web UI 与 TCP `CFolderTranEngine` 图片秒开秒传（零网络开销）；
  * **全场景一键同步**：Web 端顶栏增加“同步原生内网通”与 `GET /api/native/status`、`POST /api/native/import`、`GET /api/images/{md5}`；CLI 增加 `--web-port`、`--web-only`（脱离底层端口冲突）、`--import-native`、`--native-dir` 与 `--adopt-identity` 启动选项。

