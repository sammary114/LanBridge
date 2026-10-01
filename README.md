# LanBridge

LanBridge 是一个用于深度研究与分析 Windows 局域网即时通信软件（内网通 / IMO 3.4.3055）网络协议、并在此基础上构建原生兼容客户端与 SDK 的工程。

本项目严格遵循**真实抓包证据驱动**与**逆向汇编核验**原则：
* 所有协议解码必须有具体抓包帧号与原始字节对照。
* 核心信令与密码算法通过 PE 汇编（Capstone 反汇编）与动态抓包双重交叉印证。
* 仅在自有测试身份和受控实验网络（宿主机与 Windows Sandbox/虚拟机）中测试。

---

## 阶段进展总览

| 里程碑 | 内容 | 状态 | 关键成果 |
| :--- | :--- | :---: | :--- |
| **M1** | 专用 PCAPNG 抓包分析器 | **已交付** | 支持会话聚合、Nwt 二进制与 HTTP 上报解码、JSON 导出 |
| **M2** | 协议深度逆向与归档 | **已交付** | 破解 32 轮 XTEA 对称加密，固化 ENet 可靠 UDP 传输协议与握手时序 |
| **M3** | 仿真发包与多维抓包验证 | **已交付** | 归档 4 组实机抓包样本，全面还原冷启动广播、点对点加密与分片机制 |
| **M4** | 原生客户端模拟器 (Bot) | **已交付** | 成功在 Sandbox 原生内网通联系人列表中点亮、通过 UDP 9012 双向收发文本消息 |
| **M5** | 协议库 SDK 封装与高级特性 | **进行中** | 整理为通用客户端库，逆向完成窗口抖动、文件传输（TCP 2440）、消息撤回信令规范 |

---

## 项目结构

```text
LanBridge/
├── AGENTS.md               # 项目背景、实验环境、上下文规则与协议规范
├── README.md               # 项目说明、快速上手与测试指南
├── captures/               # 真实抓包样本与测试流量归档
│   ├── nwt.pcapng          # 样本 1：宿主机与 Sandbox 初始通信与 HTTP 上报 (49 帧)
│   ├── 02-discovery-trigger.pcapng  # 样本 2：状态切换与在线广播
│   ├── 03-sandbox-discovery.pcapng  # 样本 3：Sandbox 冷启动完整 7 阶段握手
│   └── 04-text-message.pcapng       # 样本 4：双向原生文本消息收发与输入状态
├── docs/                   # 协议研究与实验设计文档
│   ├── protocol-notes.md   # 内网通 3.4.3055 报文格式、字段偏移与 XTEA 密码机剖析
│   └── experiments.md      # 分阶段抓包验证清单与高级特性实机测试 TODO
├── tools/                  # 工具集
│   ├── pcap-analyzer/      # 本地 PCAP/PCAPNG 命令行分析器
│   │   ├── __init__.py
│   │   └── analyzer.py
│   └── net-tester/         # 原生客户端仿真器与协议驱动
│       ├── __init__.py
│       ├── crypto_engine.py # XTEA 32 轮加解密引擎 (含 AES/Blowfish 支持)
│       ├── enet_protocol.py # ENet 可靠 UDP (0x80/0x00) 状态机与拆装包
│       └── tester.py        # 原生客户端模拟器命令行工具 (支持点亮与自动应答)
├── tests/                  # 自动化测试用例
│   ├── fixtures/           # 合成测试 PCAP 样本
│   │   └── synthetic.pcap
│   ├── test_analyzer.py    # PCAP 分析器测试 (16 项)
│   └── test_net_tester.py  # 协议栈、密码机与客户端模拟器测试 (27 项)
└── reports/                # 导出的机器可读分析结果
    └── analysis.json
```

---

## 环境准备与依赖

### 1. 系统要求
* 操作系统：Windows 10 / 11 (64 位)
* Python 版本：Python 3.10+（开发环境已验证：Python 3.12.10）
* Wireshark / Npcap / Windows Sandbox（用于隔离实验与真实抓包）

### 2. 安装依赖
本项目仅依赖轻量网络报文解析库 `scapy`：

```powershell
pip install scapy
```

---

## 工具使用指南

### 一、原生客户端模拟器 (`tools/net-tester/tester.py`)

原生客户端模拟器能够以 `LanBridge-Bot` 的虚拟身份接入局域网，与真实内网通客户端完成握手、点亮好友列表，并支持交互式聊天或自动回显应答。

#### 1. 监听并点亮联系人列表（服务端模式）
在宿主机绑定 UDP 9011 与 9012 端口，监听 Sandbox 原生客户端发来的发现广播：
```powershell
python tools/net-tester/tester.py --server --ip 172.31.112.1 --auto-reply
```
* 当 Sandbox 启动内网通后，双方自动完成 7 阶段握手。
* Sandbox 联系人列表中将点亮 `LanBridge-Bot`，头像显示绿色在线徽标。
* 开启 `--auto-reply` 后，Sandbox 发送的任何文字消息都会收到自动回显应答。

#### 2. 主动握手连接 Sandbox 客户端（客户端模式）
如果 Sandbox 内网通已经在运行，可直接主动发起连接与状态通告：
```powershell
python tools/net-tester/tester.py --target-ip 172.31.122.7 --handshake
```

#### 3. 向对端发送原生消息
```powershell
python tools/net-tester/tester.py --target-ip 172.31.122.7 --send-msg "你好，这是来自 LanBridge 的测试消息"
```

---

### 二、抓包分析器 (`tools/pcap-analyzer/analyzer.py`)

专为内网通协议逆向设计的离线分析工具。

#### 1. 打印摘要与会话流统计
```powershell
python tools/pcap-analyzer/analyzer.py captures/nwt.pcapng --summary
```

#### 2. 导出 JSON 分析结果
```powershell
python tools/pcap-analyzer/analyzer.py captures/04-text-message.pcapng --json reports/analysis.json
```

#### 3. 按端口或 IP 过滤输出 Hexdump
```powershell
python tools/pcap-analyzer/analyzer.py captures/04-text-message.pcapng --port 9012 --hexdump
```

---

## 协议核心发现

### 1. 网络分层架构

| 层次 | 协议 / 格式 | 说明 |
| :--- | :--- | :--- |
| **设备发现** | UDP 9011 | 广播或定向发送 304 字节固定结构体，通报用户 ID、组织号与通讯端口 |
| **传输层** | ENet (UDP 9012) | 采用标准 ENet 可靠传输机制（`0x8000` 请求，`0x0000` ACK 回显，含 Ping、Reliable、Fragment） |
| **密码层** | XTEA 对称加密 | 32 轮迭代，硬编码 128 位密钥 `b'8asfhj@k7*20hbla'`，载荷采用 GBK 编码 |
| **应用层** | XML 载荷 Envelope | `<X_* docver="1">` 节点序列，头部包含 2 字节 Opcode 与 4 字节数据长度 |
| **兼容互通** | UDP 2425 (IPMSG) | 兼容飞鸽/飞秋协议，报文携带 `@shiyeline` 标记与在线通告 |
| **文件数据面** | TCP 2440 | 点对点高速二进制流传输，由控制面 UDP 交换 `TASK_ID` 与 `PWD` 校验后拉取 |

### 2. 核心 Opcode 映射表

| Opcode (Hex) | Opcode (Dec) | XML 标签 / 功能 | 业务说明 |
| :--- | :--- | :--- | :--- |
| `0x03E8` | 1000 | `<X_HANDSHARK>` | 身份档案同步（昵称、签名、部门、头像、版本号） |
| `0x03E9` | 1001 | `<X_CHANGE_STATUS>` | 在线状态切换（我在线上、离开、忙碌、离线） |
| `0x03EC` | 1004 | `<X_SEND_MSG>` | 文本消息发送；当内部 JSON `"type": "6"` 时为**消息/文件撤回** |
| `0x03ED` | 1005 | `<X_SEND_MSG_ACK>` | 消息送达确认回执（包含目标消息 ID 与序列号） |
| `0x03EE` | 1006 | `<X_SEND_RECEIPT>` | 消息已读回执 |
| `0x03EF` | 1007 | `<X_SEND_FLASH_SCREEN>` | **窗口抖动 / 闪屏**（`<TYPE>0</TYPE>`，触发窗口震荡与音效） |
| `0x03F0` | 1008 | `<X_SEND_WRITTING>` | 正在输入状态通知（78 字节加密包） |
| `0x03F2` | 1010 | `<X_OPERATE_SEND_FILE>` | 发送方文件操作（取消发送） |
| `0x03F3` | 1011 | `<X_OPERATE_RECV_FILE>` | 接收方文件操作（`OP=1` 接受下载 / `OP=2` 拒绝） |
| `0x03F4` | 1012 | `<X_PROGRESS_RECV_FILE>` | 文件传输进度与实时速率同步 |
| `0x03F8` | 1016 | `<X_HEARTBEAT>` | 周期性保活心跳 |
| `0x03F9` | 1017 | `<X_QUIT>` | 下线通告 |
| `0x03FA` | 1018 | `<X_READY>` | 握手完成准备就绪 |

---

## 自动化测试

项目内置 43 项自动化单元与集成测试，覆盖抓包分析、XTEA 密码机、ENet 传输协议与信令组包：

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

全部测试均在 3 秒内执行完毕并保持 100% 通过（43/43 PASS）。
