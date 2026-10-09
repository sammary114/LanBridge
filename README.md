# AstrBot 内网通平台适配器插件 (astrbot_plugin_lanbridge)

[![Tests](https://img.shields.io/badge/tests-33%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![AstrBot](https://img.shields.io/badge/AstrBot-%3E%3D4.0.0-orange.svg)](https://astrbot.app)

本项目是基于 [AstrBot](https://astrbot.app) 官方平台适配器规范开发的 **内网通（Nwt / IMO 3.4.3055）平台适配器插件**。

通过本适配器，AstrBot 可以作为真实的局域网即时通讯联系人直接点亮在内网通官方客户端的联系人列表中，赋予局域网用户与大模型（LLM）对话、执行插件技能（Skills）、调用工具（Tools）的能力。

---

## 核心特性

- **原生协议级兼容**：完全还原内网通可靠 UDP 传输协议（ENet 协议栈）与 32 轮 XTEA 密码机（GBK 编码）。
- **零额外 C 扩展依赖**：核心网络与加密引擎完全基于 Python 原生 `asyncio`、`socket` 与 `struct` 实现，轻量、稳定、高并发。
- **自动握手与好友列表点亮**：支持监听 UDP 9011 发现广播，自动应答 304 字节发现帧与 `<X_HANDSHARK>` 名片信令，在内网通端显示在线绿色徽标。
- **双向即时会话（私聊 & 群聊）**：
  - 自动接收内网通私聊与多人讨论组（QGroup）文本消息，转为 AstrBot 的标准 `MessageChain` 提交核心处理管道。
  - 支持将大模型回复渲染回内网通客户端（富文本 JSON 封包与自动送达回执 ACK）。
- **图片双向原图收发**：
  - 内置原生 `CFolderTranEngine` TCP 9013 微文件传输引擎。
  - 支持双向无损收发高清图片（支持私聊及讨论组群图片分片流传与 MD5 校验）。
- **高级交互与状态机制**：
  - 自动触发正在输入指示（`<X_SEND_WRITTING>`），提供更真实的 AI 打字体验。
  - 支持动态切换机器人在线状态（`/lanbridge_status 1=在线/2=离开/3=忙碌/4=离线`）。
  - 支持检测与响应窗口抖动（`<X_SEND_FLASH_SCREEN>`）。
  - 支持 84 种内网通原生表情与 Emoji 双向映射转换。
  - 支持消息防超时重传与分片组装（SendFragment 0x88 拆装包）。

---

## 插件目录结构

```text
astrbot_plugin_lanbridge/
├── metadata.yaml           # AstrBot 插件元数据与版本声明
├── main.py                 # 插件主入口 (Star 插件类，注册指令)
├── adapter.py              # 平台适配器主类 (继承 Platform)
├── event.py                # 消息事件类 (继承 AstrMessageEvent)
├── compat.py               # AstrBot 运行时兼容层与测试桩
├── lanbridge/              # 内置通用异步 LanBridge (Nwt) 协议客户端
│   ├── __init__.py         # 导出客户端接口
│   ├── client.py           # 高层异步客户端 (LanBridgeClient)
│   ├── crypto.py           # 32 轮 XTEA 块密码机 (密钥 b'8asfhj@k7*20hbla')
│   ├── enet.py             # ENet 可靠 UDP (0x80/0x00, 0x88 分片重组) 状态机
│   └── protocol.py         # XML 信令编解码器与 304B 发现封包
├── tests/                  # 自动化单元测试集 (17 项全部通过)
│   ├── __init__.py
│   ├── test_lanbridge_sdk.py
│   └── test_astrbot_adapter.py
├── requirements.txt        # 依赖清单 (纯标准库)
├── .gitignore
└── README.md               # 插件说明文档
```

---

## 安装与部署

### 方式一：直接克隆到 AstrBot 插件目录（推荐）

进入您的 AstrBot 根目录下的 `data/plugins/` 文件夹：

```bash
cd AstrBot/data/plugins
git clone -b astrbot-adapter <本仓库地址> astrbot_plugin_lanbridge
```

### 方式二：在 AstrBot WebUI 中安装

1. 打开 AstrBot 控制台 WebUI。
2. 导航至 **插件** -> **安装插件**。
3. 输入本仓库 Git 地址并指定分支 `astrbot-adapter` 进行安装。

---

## 配置说明

插件加载后，在 AstrBot WebUI 的“平台”或插件设置中可以配置以下参数（也可在 `data/config.json` 中配置）：

| 配置项 | 类型 | 默认值 | 说明 |
| :--- | :---: | :---: | :--- |
| `bind_ip` | string | `"0.0.0.0"` | 绑定的本地网卡 IP（如果使用虚拟机/Sandbox，填宿主机虚拟网卡 IP，例如 `172.31.112.1`） |
| `discovery_port` | int | `9011` | 内网通设备发现与广播端口（默认 `9011`） |
| `data_port` | int | `9012` | 内网通私有 ENet 数据通讯端口（默认 `9012`） |
| `image_port` | int | `9013` | CFolderTranEngine TCP 图片传输端口（默认 `9013`） |
| `bot_name` | string | `"LanBridge-AI助手"` | 显示在内网通好友列表中的昵称 |
| `bot_sign` | string | `"由 AstrBot 驱动的内网通 AI 助手"` | 显示在好友名片中的签名 |
| `corp_id` | string | `""` | 组织号（若内网通客户端设置了组织号，两端需保持一致） |
| `auto_shake_back` | bool | `false` | 当收到内网通好友发送的窗口抖动时，是否自动反向抖动对端 |
| `auto_typing` | bool | `true` | 收到私聊消息时，是否自动向好友发送“正在输入”状态提示 |

---

## 本地测试与开发

无需安装完整 AstrBot 宿主环境，本项目内置完备的 Mock 运行桩，可直接执行全套自动化单元测试：

```powershell
python -m unittest discover -s tests -p "test_*.py" -v
```

**测试输出示例**：
```text
test_adapter_metadata (test_astrbot_adapter.TestAstrBotAdapter.test_adapter_metadata) ... ok
test_convert_message (test_astrbot_adapter.TestAstrBotAdapter.test_convert_message) ... ok
test_event_send_plain (test_astrbot_adapter.TestAstrBotAdapter.test_event_send_plain) ... ok
test_handle_msg_commits_event (test_astrbot_adapter.TestAstrBotAdapter.test_handle_msg_commits_event) ... ok
test_plugin_init (test_astrbot_adapter.TestAstrBotAdapter.test_plugin_init) ... ok
test_send_by_session (test_astrbot_adapter.TestAstrBotAdapter.test_send_by_session) ... ok
test_client_config (test_lanbridge_sdk.TestLanBridgeSDK.test_client_config) ... ok
test_discovery_packet_roundtrip (test_lanbridge_sdk.TestLanBridgeSDK.test_discovery_packet_roundtrip) ... ok
test_enet_session_fragmentation (test_lanbridge_sdk.TestLanBridgeSDK.test_enet_session_fragmentation) ... ok
test_enet_session_reliable_and_ack (test_lanbridge_sdk.TestLanBridgeSDK.test_enet_session_reliable_and_ack) ... ok
test_flash_screen_xml (test_lanbridge_sdk.TestLanBridgeSDK.test_flash_screen_xml) ... ok
test_handshake_xml (test_lanbridge_sdk.TestLanBridgeSDK.test_handshake_xml) ... ok
test_recall_msg_xml (test_lanbridge_sdk.TestLanBridgeSDK.test_recall_msg_xml) ... ok
test_event_send_group_text_and_image (test_astrbot_adapter.TestAstrBotAdapter.test_event_send_group_text_and_image) ... ok
test_event_send_image_1v1 (test_astrbot_adapter.TestAstrBotAdapter.test_event_send_image_1v1) ... ok
test_event_typing (test_astrbot_adapter.TestAstrBotAdapter.test_event_typing) ... ok
test_folder_tran_packets (test_lanbridge_sdk.TestLanBridgeSDK.test_folder_tran_packets) ... ok
test_qgroup_send_and_extract (test_lanbridge_sdk.TestLanBridgeSDK.test_qgroup_send_and_extract) ... ok
test_send_image_xml (test_lanbridge_sdk.TestLanBridgeSDK.test_send_image_xml) ... ok
test_xtea_envelope_packing (test_lanbridge_sdk.TestLanBridgeSDK.test_xtea_envelope_packing) ... ok

----------------------------------------------------------------------
Ran 33 tests in 0.111s

OK
```

---

## 开源协议与声明

本项目仅供局域网协议兼容性研究与内网智能化助手集成使用。
内网通（IMO）商标与知识产权归其原开发商所有。
