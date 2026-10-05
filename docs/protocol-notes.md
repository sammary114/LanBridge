# 内网通（Nwt / IMO）3.4.3055 协议分析笔记

> **状态**：第一阶段初稿（基于 `captures/nwt.pcapng` 真实抓包）  
> **核心原则**：以真实抓包帧为唯一事实依据，不凭端口号臆测功能，区分事实、高置信度推测与待验证假设。

---

## 1. 抓包总体概况

抓包文件：`captures/nwt.pcapng`（SHA256: `521f2367351a6a3b95d5e45327b86131a8273ee61c869ba325262b3651b76544`，文件大小 19,764 字节）。

* **总数据包数**：49 帧
* **时间跨度**：`2026-10-01 11:05:38.957587 UTC` ~ `2026-10-01 11:06:19.904846 UTC`（持续 40.9473 秒）
* **涉及端点**：
  * `172.31.112.1`：宿主机虚拟网卡接口（Hyper-V / Sandbox 默认网关）
  * `172.31.122.254`：Windows Sandbox 内部虚拟 IP
  * `47.57.13.180`：公网 IP（内网通上报服务器 `report.51nwt.com`）
  * `20.184.175.2`：公网 IP（微软遥测 `mobile.events.data.microsoft.com`）
  * `204.79.197.203`：公网 IP（微软证书吊销列表 OCSP 服务器）
* **传输层协议分布**：
  * TCP：39 帧
  * UDP：10 帧

---

## 2. 流量分类与关联度判定

根据应用层特征与通信行为，抓包中的 49 帧可划分为三类：

| 类别 | 传输层 | 对应端点 | 帧范围 | 业务属性 | 关联内网通置信度 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A. 本地内网通点对点协议** | UDP 9012 | `172.31.112.1:9012` <-> `172.31.122.254:9012` | #8, #9, #10, #11, #12, #13, #46, #47, #48, #49 (共 10 帧) | 私有二进制协议（心跳与数据交互） | **已确认（100%）** |
| **B. 外部内网通状态上报** | TCP 80 | `172.31.122.254:55778/55777` <-> `47.57.13.180:80` | #1~#7, #44~#45 (共 9 帧) | HTTP POST `/api/report.php` | **已确认（100%）** |
| **C. Windows 系统遥测与 OCSP** | TCP 443, 80 | `172.31.122.254` <-> `20.184.175.2:443`, `204.79.197.203:80` | #14~#43 (共 30 帧) | TLS 握手与 OCSP 证书校验 | **无关（系统背景流量）** |

> [!IMPORTANT]
> **排噪结论**：类别 C 中包含微软遥测域名 `mobile.events.data.microsoft.com` 与 `Microsoft-CryptoAPI` 发起的 OCSP 证书请求，属于 Windows Sandbox 启动时的底层系统活动，**不是内网通协议**，后续协议逆向应将其完全过滤。

---

## 3. 本地点对点协议分析（UDP 9012）

### 3.1 总体行为特征
抓包中观察到的 10 个 UDP 数据包全部运行在 `UDP 9012` 端口，呈现严格的 **Request-Response (请求-确认)** 配对机制。每次请求发出后，接收方均在 60~105ms 内返回确认帧（ACK）。

```text
Host (172.31.112.1:9012)                 Sandbox (172.31.122.254:9012)
       |                                                |
       |--- Frame #8: REQ (seq=0x9c7e, 44B) ----------->| (t=2.26s)
       |<-- Frame #9: ACK (seq=0x9c7e, 10B) ------------| (t=2.33s, +69ms)
       |                                                |
       |<-- Frame #10: REQ (seq=0xef58, 8B) ------------| (t=8.76s)
       |--- Frame #11: ACK (seq=0xef58, 10B) ---------->| (t=8.82s, +60ms)
       |                                                |
       |<-- Frame #12: REQ (seq=0xf66a, 44B) -----------| (t=10.57s)
       |--- Frame #13: ACK (seq=0xf66a, 10B) ---------->| (t=10.67s, +105ms)
       |                                                |
       |--- Frame #46: REQ (seq=0x1243, 8B) ----------->| (t=32.41s)
       |<-- Frame #47: ACK (seq=0x1243, 10B) -----------| (t=32.48s, +73ms)
       |                                                |
       |<-- Frame #48: REQ (seq=0x6caa, 8B) ------------| (t=40.84s)
       |--- Frame #49: ACK (seq=0x6caa, 10B) ---------->| (t=40.94s, +102ms)
```

### 3.2 报文格式剖析

#### 1. 请求报文头部（Request Header，固定 8 字节）
所有请求报文（8 字节或 44 字节）均具有相同的基础头部结构：

| 偏移（Offset） | 长度（Bytes） | 字节序 | 字段名 | 观察到的取值 | 置信度 | 字段解释 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `0x00 ~ 0x01` | 2 | Big Endian | `flag_magic` | `0x8000` | 高 | 报文类型标识。最高位 1 (`0x80`) 标识此帧为主动请求/命令 |
| `0x02 ~ 0x03` | 2 | Big Endian | `seq_id` | `0x9c7e`, `0xef58`, `0xf66a`, `0x1243`, `0x6caa` | 已确认 | 事务/报文序列号（Transaction ID），在对应的 ACK 尾部原样返回 |
| `0x04` | 1 | - | `opcode` | `0x85` (心跳), `0x86` (数据交互) | 高 | 命令操作码 |
| `0x05` | 1 | - | `modifier` | `0xff` (当 opcode=0x85), `0x00` (当 opcode=0x86) | 中 | 操作码子标志/修饰符 |
| `0x06 ~ 0x07` | 2 | Big Endian | `sub_id / chan` | `0x0004`, `0x0005` (心跳递增计数或会话句柄); `0x0006` (数据通道) | 中 | 子通道标识或通道流水号 |

#### 2. 心跳/探测报文（Opcode `0x85`，总长 8 字节）
* **证据帧**：
  * Frame #10: `80 00 ef 58 85 ff 00 04`
  * Frame #46: `80 00 12 43 85 ff 00 05`
  * Frame #48: `80 00 6c aa 85 ff 00 05`
* **分析**：无后续载荷，末尾 2 字节（`00 04` -> `00 05`）呈现单调递增态势，用于维持双向端点存活。

#### 3. 数据交互报文（Opcode `0x86`，总长 44 字节）
* **证据帧**：
  * Frame #8 (Host -> Sandbox):  
    `80 00 9c 7e 86 00 00 06 00 22 00 00 00 22 00 00 03 f8 d5 29 c5 43 9d e0 45 c9 d3 dc 11 86 67 69 e1 fe df a8 96 e8 e7 04 a5 53 2f 3e`
  * Frame #12 (Sandbox -> Host):  
    `80 00 f6 6a 86 00 00 06 00 22 00 00 00 22 00 00 03 f8 d5 29 c5 43 9d e0 45 c9 d3 dc 11 86 67 69 e1 fe df a8 96 e8 e7 04 a5 53 2f 3e`

* **扩展字段解析**：

| 偏移（Offset） | 长度（Bytes） | 字节序 | 字段名 | 取值 | 置信度 | 解释 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `0x08 ~ 0x09` | 2 | Big Endian | `remaining_len` | `0x0022` (十进制 34) | 已确认 | 后续剩余载荷总长度（44 字节总长 - 10 字节 = 34 字节） |
| `0x0A ~ 0x0B` | 2 | Big Endian | `flags / reserved`| `0x0000` | 低 | 扩展保留位 |
| `0x0C ~ 0x0D` | 2 | Big Endian | `inner_len` | `0x0022` (十进制 34) | 中 | 内部数据单元长度声明 |
| `0x0E ~ 0x0F` | 2 | Big Endian | `reserved` | `0x0000` | 低 | 保留字段 |
| `0x10 ~ 0x2B` | 28 | - | `payload_data` | `03 f8 d5 29 c5 43 9d e0 ... 2f 3e` | 已确认存在，含义待定 | 28 字节实体数据。**极为关键的是：Host 发送与 Sandbox 发送的这 28 字节完全一致！** |

> [!NOTE]
> **关于 28 字节载荷的假设**：
> 1. **组织/网络标识码（Org Token）**：内网通设置中包含“组织号”。若宿主机与 Sandbox 处于同一虚拟子网，可能派生出相同的 28 字节广播/共享凭据。
> 2. **加密摘要 / 密钥材料**：可能由本地机器特征或双方公认的种子计算生成。需要设计“修改组织号后重新抓包”的对照实验进行验证。

#### 4. 状态切换通告报文（Opcode `0x86`，总长 82 字节 / Wire 124 字节）

* **证据文件**：`captures/02-discovery-trigger.pcapng`（SHA256: `d694f56a25b4d8a9a37884539edfb64aed5c80a95ccbf2c68871dacf425fb4cb`）
* **证据帧**：
  * Frame #1 (t=0.000s, 状态变更为“离开”):
    `80 00 fd 9e 86 00 00 47 00 48 00 00 00 48 00 00 03 e9 36 af 74 16 55 c8 6a 85 92 29 11 3f 68 83 a3 1e 3a 64 3f a2 3c 20 e0 ae c1 aa f8 95 d8 ce 4c a9 [68 25 65 1d aa 0f 80 17] 5e d2 4a 2c 45 3c 12 f2 09 d3 b6 36 73 13 41 36 18 96 6a 88 9a 6e 34 90`
  * Frame #7 (t=5.130s, 状态变更为“我在线上”):
    `80 00 11 a8 86 00 00 48 00 48 00 00 00 48 00 00 03 e9 36 af 74 16 55 c8 6a 85 92 29 11 3f 68 83 a3 1e 3a 64 3f a2 3c 20 e0 ae c1 aa f8 95 d8 ce 4c a9 [8a 32 4c 97 21 14 60 75] 5e d2 4a 2c 45 3c 12 f2 09 d3 b6 36 73 13 41 36 18 96 6a 88 9a 6e 34 90`

* **重大发现：8 字节分组密码（Blowfish）加密特征**：
  1. **长度规律**：82 字节 UDP payload = 10 字节基础头 + 6 字节扩展头 + 2 字节类型标记（`0x03 0xe9`）+ **整整 64 字节数据（8 个 8 字节密码分组）**。
  2. **二进制扫描证据**：在 `ShiYeLine.exe` 进程映像中，明确扫描到 Blowfish 算法标准初始化常数（`P0 = 0x243f6a88`，π 的小数部分展开）。
  3. **单分组状态置换**：比对“离开”与“我在线上”两帧，在总计 82 字节中，除了递增的序号和计数器外，**64 字节载荷中仅有第 5 个 8 字节分组（偏移 0x32~0x39）发生改变**，其余 7 个分组（56 字节）完全一致！
     * 状态“离开”对应第 5 分组：`68 25 65 1d aa 0f 80 17`
     * 状态“在线”对应第 5 分组：`8a 32 4c 97 21 14 60 75`
  4. **结论**：内网通状态数据使用 8 字节分组密码（极大概率为 Blowfish-ECB）加密，第 5 分组为加密后的状态字段。

#### 5. 确认应答报文（ACK，固定 10 字节）
所有 ACK 具有严格一致的 10 字节结构：

| 偏移（Offset） | 长度（Bytes） | 字节序 | 字段名 | 观察值 | 置信度 | 解释 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `0x00 ~ 0x01` | 2 | Big Endian | `ack_magic` | `0x0000` | 高 | 确认标志（最高位为 0） |
| `0x02 ~ 0x03` | 2 | Big Endian | `ack_code` | `0x0100` (针对 0x86), `0x01ff` (针对 0x85) | 高 | 应答状态字（与请求中的 opcode/modifier 对应） |
| `0x04 ~ 0x05` | 2 | Big Endian | `echo_chan_1` | 镜像请求帧中的通道/计数参数 | 高 | 回显通道参数 |
| `0x06 ~ 0x07` | 2 | Big Endian | `echo_chan_2` | 镜像请求帧中的通道/计数参数 | 高 | 二次冗余回显 |
| `0x08 ~ 0x09` | 2 | Big Endian | `ack_seq_id` | 请求报文偏移 `0x02~0x03` 的 `seq_id` | **已确认** | 确认收到的事务 ID |

#### 7. 文本消息与分片传输报文（Opcode `0x88`，分片传输）

* **证据文件**：`captures/04-text-message.pcapng`（SHA256: `1fb6f7da37ed088d1d95729cab02db86a32acba7eae1b3a7ebd8b3cd9aeae8fd`）
* **通信过程**：Sandbox（`172.31.122.254:9012`）向宿主机（`172.31.112.1:9012`）发送文本消息 `hello123`。
* **分片帧特征**：由于消息封包总长达到 1519 字节（超过单帧 UDP 最佳 MTU），内网通自动启用了 **Opcode 0x88 分片传输机制**，拆分为 2 帧发送：
  * Frame #3（分片 1/2）：Wire 1442 字节，UDP Payload 1400 字节，承载前 1372 字节消息数据。
  * Frame #4（分片 2/2）：Wire 217 字节，UDP Payload 175 字节，承载剩余 147 字节消息数据。
  * $1372 + 147 = 1519$ 字节，正好等于完整消息总长！

* **Opcode 0x88 分片头部结构（固定 28 字节）**：

| 偏移（Offset） | 长度（Bytes） | 字节序 | 字段名 | 观察值（Frame #3 / #4） | 解释 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `0x00 ~ 0x01` | 2 | Big Endian | `magic` | `0x8000` | 主动请求/数据标志 |
| `0x02 ~ 0x03` | 2 | Big Endian | `seq_id` | `0xee3e` | 统一的事务/消息序列号 |
| `0x04 ~ 0x05` | 2 | Big Endian | `opcode` | `0x8800` | **Opcode 0x88（分片数据传输）** |
| `0x06 ~ 0x07` | 2 | Big Endian | `sub_id` | `0x004c` (分片0), `0x004d` (分片1) | 当前分片子序列号 |
| `0x08 ~ 0x09` | 2 | Big Endian | `base_id` | `0x004c` | 起始分片子序列号 |
| `0x0A ~ 0x0B` | 2 | Big Endian | `frag_len` | `0x055c` (1372), `0x0093` (147) | 当前分片数据字节数 |
| `0x0C ~ 0x0F` | 4 | Big Endian | `total_frags`| `0x00000002` (2) | **总分片数** |
| `0x10 ~ 0x13` | 4 | Big Endian | `frag_index`| `0x00000000` (0), `0x00000001` (1) | **当前分片索引（从 0 计数）** |
| `0x14 ~ 0x17` | 4 | Big Endian | `total_msg_len`| `0x000005ef` (1519) | **重组后完整报文总长度** |
| `0x18 ~ 0x1B` | 4 | Big Endian | `frag_offset`| `0x00000000` (0), `0x0000055c` (1372)| **当前分片在总报文中的起始偏移量** |
| `0x1C ~ 尾部` | 变长 | - | `fragment_data`| 1372 字节 / 147 字节 | 分片实际承载数据 |

* **多分片联合确认（MultiACK）**：
  * Frame #5 宿主机返回 18 字节 ACK：`00 00 01 00 00 4c 00 4c ee 3e 01 00 00 4d 00 4d ee 3e`。
  * 一次性同时确认了分片 0（`0x004c`）与分片 1（`0x004d`）。

#### 8. 应用层 XML 格式与加密封装剖析

逆向提取 `ShiYeLine.exe` 进程映像，发现内网通业务层采用了高度统一的 XML 格式：

##### 1. 发送消息模板：
```xml
<X_SEND_MSG docver="%u">
    <MSG_ID>%llu</MSG_ID>
    <RECEIPT>%u</RECEIPT>
    <MSG>%s</MSG>
    <MSG_TIME>%llu</MSG_TIME>
    <OFFLINE>%u</OFFLINE>
    <HIDE_RECORD>%u</HIDE_RECORD>
</X_SEND_MSG>
```

##### 2. 消息送达回执（ACK）模板：
```xml
<X_SEND_MSG_ACK docver="%u">
    <MSG_ID>%llu</MSG_ID>
</X_SEND_MSG_ACK>
```

##### 3. 完整报文载荷结构（1519 字节）：
$$1519\text{ 字节} = 16\text{ 字节头部} + 1496\text{ 字节密文} + 7\text{ 字节末尾明文标签}$$

* **前 16 字节头部**：
  * `0x00~0x03`：`00 00 05 ef`（总长 1519 字节）
  * `0x04~0x05`：`00 00`（保留字段）
  * `0x06~0x07`：`0x03 0xec`（`0x03` 为版本，`0xec` 为 `X_SEND_MSG` 操作码）
  * `0x08~0x0F`：`69 e9 b7 54 d9 8b a0 61`（双方协商绑定的 8 字节 Session Token / 会话密钥句柄）
* **密文部分**：整整 1496 字节，**恰好为 $187 \times 8$ 字节分组**（Blowfish 加密）。
* **尾部明文**：`ND_MSG>`（对应闭合标签 `</X_SEND_MSG>` 未填满 8 字节密码分组的剩余明文字符）。

##### 4. 交互时序闭环：
1. **输入中提示**（Frame #1, #8）：发送 Opcode 0x86，子类型 `0x03 0xf0`，尾部标签为 `ING>`（`<X_TYPING>`）。
2. **文本传输**（Frame #3, #4）：发送 Opcode 0x88 分片传输入 `<X_SEND_MSG>`，尾部标签为 `ND_MSG>`。
3. **传输级确认**（Frame #5）：返回 MultiACK 确认收全 UDP 分片。
4. **业务级回执**（Frame #6）：宿主机发送 Opcode 0x86，子类型 `0x03 0xed`，尾部标签为 `G_ACK>`（`<X_SEND_MSG_ACK>`）。
5. **回执确认**（Frame #7）：Sandbox 对业务回执进行 ACK 确认。

---

## 4. 外部上报协议分析（HTTP POST）

* **证据帧**：Frame #4（Frame #1~#3 为三次握手，Frame #5~#7 为应答与确认）
* **请求端点**：`172.31.122.254:55778` -> `47.57.13.180:80`
* **HTTP 头**：
  ```http
  POST /api/report.php HTTP/1.1
  Host: report.51nwt.com
  Accept: */*
  Content-Length: 773
  Content-Type: application/x-www-form-urlencoded
  ```
* **解密后的 URL-encoded 请求体**：
  ```json
  json={
     "app" : "syl",
     "build num" : "3055",
     "corp id" : "296becfde55172409ef2b81908044747",
     "corp time" : "1494217112",
     "ip" : "172.31.122.254",
     "mac" : "00155d15446e",
     "major num" : "3",
     "minor num" : "4",
     "name" : "B070939D-A",
     "sex" : "0",
     "type" : "user",
     "user id" : "3b9d1aadecebe74f8ea1cb3af56538fc",
     "user list" : "2158b475dfcfdd43989482c4dcf0337b.1;3b9d1aadecebe74f8ea1cb3af56538fc.1;"
  }
  ```

### 字段含义明确表：
1. `app`: `"syl"`（ShiYeLine 拼音首字母，内网通主进程名）
2. `major num` / `minor num` / `build num`: `"3"`, `"4"`, `"3055"`（对应版本 3.4.3055）
3. `corp id`: 32 位十六进制字符串（组织标识 MD5）
4. `corp time`: `"1494217112"`（Unix 时间戳，对应 2017-05-08 04:18:32 UTC）
5. `ip`: 当前客户端上报时使用的 IP `172.31.122.254`
6. `mac`: 客户端网卡 MAC 地址 `00:15:5d:15:44:6e`（前缀 `00:15:5d` 为微软 Hyper-V 标准分配段）
7. `name`: 主机名 `B070939D-A`
8. `user id`: 本地生成的唯一用户 ID（32 位十六进制）
9. `user list`: 已发现的联系人列表 `2158b475dfcfdd43989482c4dcf0337b.1;3b9d1aadecebe74f8ea1cb3af56538fc.1;`。其中已包含两个用户，说明在 HTTP 上报前，客户端已经完成了本地用户发现！

* **服务器响应**：Frame #6 返回 `HTTP/1.1 404 Not Found`。表明官方上报接口目前已失效或该路径不再提供服务。

---

## 5. 冷启动上线发现与初次握手全流程（基于 `captures/03-sandbox-discovery.pcapng`）

* **证据捕获文件**：`captures/03-sandbox-discovery.pcapng`（166 帧，SHA256: `050acb19a16fbbffb4cb842cb32d03ef46cfc8ef03a620e7e1c8d5cff15ba245`）。
* **通信场景**：Sandbox 内网通客户端从零冷启动，完成网络扫描、发现宿主机客户端、协商建立私有 P2P 通道、完成个人资料同步的完整闭环。

### 5.1 UDP 9011 私有用户发现报文（固定 304 字节，`0x00000130`）

内网通启动时立即向广播地址发出 304 字节固定长度二进制发现帧：

| 偏移（Offset） | 长度（Bytes） | 字节序 | 字段名 | 观察值（Frame #1 / #5） | 置信度 | 字段解释与用途 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `0x00 ~ 0x03` | 4 | Big Endian | `total_len` | `0x00000130` (304) | **已确认** | 报文总长度声明 |
| `0x04 ~ 0x07` | 4 | Big Endian | `cmd` | `0x00000001` (广播), `0x00000002` (应答), `0x00000004` (握手) | **已确认** | 发现命令码：1=广播, 2=单播回复, 4=握手内嵌 |
| `0x08 ~ 0x0B` | 4 | Big Endian | `sub_cmd` | `0x00000001` | 高 | 子命令或流水号 |
| `0x0C ~ 0x0F` | 4 | Hex | `magic` | `5f c1 d8 ec` | 高 | 客户端固定协议魔数 / 会话标识 |
| `0x10 ~ 0x13` | 4 | Big Endian | `reserved` | `0x00000000` | 中 | 保留字段 |
| `0x14 ~ 0x17` | 4 | Network | `subnet_bcast_ip`| `ac 1f 7f ff` (`172.31.127.255`) | **已确认** | 发送方网卡的子网定向广播 IP |
| `0x18 ~ 0x1D` | 6 | ASCII | `version` | `#3#4#4` | **已确认** | 内部通信协议版本号 |
| `0x1E ~ 0x3D` | 32 | ASCII | `user_id` | `3b9d1aadecebe74f8ea1cb3af56538fc` / `2158b475dfcfdd43989482c4dcf0337b` | **已确认** | 32 位十六进制用户唯一标识符 |
| `0x3E ~ 0x5F` | 34 | - | `padding` | 全 `0x00` | 高 | 保留与对齐填充 |
| `0x60 ~ 0x6F` | 16 | Hex | `instance_guid` | Sandbox: `b92cf731...`, Host: `92f64910...` | 高 | 本地客户端进程实例唯一 GUID |
| `0x70 ~ 0x9F` | 48 | - | `reserved` | 全 `0x00` | 中 | 保留字段 |
| `0xA0 ~ 0xA3` | 4 | Big Endian | `param_500` | `0x000001f4` (500) | 中 | 扫描/重试超时阈值（500ms） |
| `0xA4 ~ 0xA7` | 4 | Big Endian | `dyn_port_info`| Sandbox: `00 f5 c4 00`, Host: `00 d2 16 00` | **已确认** | **P2P 动态辅助 UDP 端口声明**：偏移 `0xA5~0xA6`（`0xf5c4`=62916, `0xd216`=53782）！ |
| `0xA8 ~ 0x12F` | 136 | - | `tail_padding` | 全 `0x00` | 高 | 尾部保留填充 |

> [!IMPORTANT]
> **动态辅助端口发现机制突破**：
> 偏移 `0xA5~0xA6`（165~166 字节）明确通告了端点的动态 UDP 通信端口（Sandbox 为 `62916`，宿主机为 `53782`）。双端在收到发现报文后，不仅向主端口 `9012` 发包，还同时向此动态端口建立双通道通信（帧 #9, #10, #12, #13）。

---

### 5.2 UDP 2425 IPMSG 兼容上线广播

内网通在发起 UDP 9011 私有广播的同时，向 `172.31.127.255:2425` 与 `255.255.255.255:2425` 双发标准飞鸽/飞秋兼容报文（证据帧 #3, #4, #51, #52, #57, #58, #121, #122, #163~166）：

* **报文原始 ASCII 格式**：
  ```text
  1@shiyeline:<packet_no>:<username>:<hostname>:1:<nickname>\x00<group_name>\x00<user_id>\x00
  ```
* **实测样例（Frame #3）**：
  ```text
  1@shiyeline:8574:WDAGUtilit:B070939D-A:1:B070939D-A\x00内网通联系人\x003b9d1aadecebe74f8ea1cb3af56538fc\x00
  ```
* **字段说明**：
  * 版本前缀：`1@shiyeline`（标准 IPMSG 为 `1`，内网通增加 `@shiyeline` 标记识别自有客户端）
  * 包序号：`8574`（递增计数）
  * 用户名与机器名：`WDAGUtilit` / `B070939D-A`
  * 命令字：`1`（`IPMSG_BR_ENTRY`，上线通告）
  * 扩展零结尾字段：昵称、分组名（`内网通联系人`，GBK 编码）、32 位 User ID。
* **重传周期**：实测每隔约 5.5 秒重复一次广播。

---

### 5.3 双端初次握手完整时序生命周期

通过对 `03-sandbox-discovery.pcapng` 的全量解析，证实客户端握手分为 7 个严格时序阶段：

```text
Sandbox (172.31.122.254)                         Host (172.31.112.1)
   |                                                      |
   |=== [阶段 1: 发现广播] (t=0.00s) =====================|
   |--- Frame #1/#2: UDP 9011 Cmd 1 (304B Bcast) -------->| (通告 Sandbox 62916 端口)
   |--- Frame #3/#4: UDP 2425 IPMSG BR_ENTRY ------------>|
   |                                                      |
   |=== [阶段 2: 发现应答] (t=0.10s) =====================|
   |<-- Frame #5/#6: UDP 9011 Cmd 2 (304B Reply) ---------| (通告 Host 53782 端口)
   |                                                      |
   |=== [阶段 3: 传输通道激活 (0x82/0x83)] (t=0.18s) =====|
   |<-- Frame #7: UDP 9012 Opcode 0x82 (52B HandshakeInit)|
   |--- Frame #8: UDP 9012 Opcode 0x83 (48B Reply) ------>|
   |--- Frame #9/#10: UDP 62916->53782 Opcode 0x82 ------>| (双向激活辅助端口)
   |<-- Frame #12/#13: UDP 53782->62916 Opcode 0x83 ------|
   |                                                      |
   |=== [阶段 4: 握手确认 (0x86 Cmd 4)] (t=0.28s) ========|
   |<-- Frame #17: UDP 9012 Opcode 0x86 (314B 发现内嵌)---| (Host 发送 Cmd 4 握手确认)
   |--- Frame #20: UDP 9012 ACK for #17 ----------------->|
   |--- Frame #21/#22: UDP 62916->53782 Opcode 0x86 ----->| (Sandbox 发送 Cmd 4 握手确认)
   |<-- Frame #25/#26: UDP 53782->62916 ACK for #21 ------|
   |                                                      |
   |=== [阶段 5: 资料同步 (0x88 X_HANDSHARK)] (t=0.38s) ==|
   |<-- Frame #23/#24: UDP 9012 Opcode 0x88 (1490B Host) -| (Host 资料分片 1/2 + 2/2)
   |--- Frame #27: UDP 9012 MultiACK for #23/#24 -------->|
   |--- Frame #30/#31: UDP 9012 Opcode 0x88 (1486B SB) -->| (Sandbox 资料分片 1/2 + 2/2)
   |<-- Frame #34: UDP 9012 MultiACK for #30/#31 ---------|
   |                                                      |
   |=== [阶段 6: 会话探测与终结 (0x86/0x8a)] (t=0.60s) ===|
   |--- Frame #35: UDP 9012 Opcode 0x86 (115B Probe) ---->| (Subtype 0x03 0xfa)
   |<-- Frame #36: UDP 9012 ACK for #35 ------------------|
   |<-- Frame #37: UDP 9012 Opcode 0x86 (115B Probe) -----|
   |--- Frame #38: UDP 9012 ACK for #37 ----------------->|
   |<-- Frame #39: UDP 9012 Opcode 0x8a (16B Done) -------|
   |--- Frame #40: UDP 9012 ACK for #39 ----------------->|
   |--- Frame #41: UDP 9012 Opcode 0x8a (16B Done) ------>|
   |<-- Frame #42: UDP 9012 ACK for #41 ------------------|
   |                                                      |
   |=== [阶段 7: 共享凭据锁定 (0x86 0x03f8)] (t=1.69s) ===|
   |<-- Frame #43: UDP 9012 Opcode 0x86 (44B 28B Token) --|
   |--- Frame #44: UDP 9012 ACK for #43 ----------------->|
   |--- Frame #47: UDP 9012 Opcode 0x86 (44B 28B Token) ->|
   |<-- Frame #50: UDP 9012 ACK for #47 ------------------|
```

---

### 5.4 握手核心 XML 架构提取（`<X_HANDSHARK>`）

逆向二进制确认阶段 5 传输的分片数据为 UTF-16LE 编码的 XML 结构（源码拼写确实为 `HANDSHARK` 而非 `HANDSHAKE`）：

```xml
<X_HANDSHARK docver="%u">
    <FEATURE>
        <MAJOR>%s</MAJOR>
        <MINOR>%s</MINOR>
        <BUILD>%s</BUILD>
        <APP>%s</APP>
        <MSG>%s</MSG>
        <FILE_TRAN>%s</FILE_TRAN>
        <FOLDER_TRAN>%s</FOLDER_TRAN>
        <REMOTE_ASSISTANCE>%s</REMOTE_ASSISTANCE>
        <FILE_SHARE>%s</FILE_SHARE>
        <QGROUP>%s</QGROUP>
        <QGROUP_MSG>%s</QGROUP_MSG>
        <QGROUP_FILE>%s</QGROUP_FILE>
        <QGROUP_FOLDER>%s</QGROUP_FOLDER>
        <OFFLINE_MSG>%s</OFFLINE_MSG>
        <OFFLINE_FILE>%s</OFFLINE_FILE>
        <LAN_UPDATE>%s</LAN_UPDATE>
        <HIDE_RECORD>%s</HIDE_RECORD>
    </FEATURE>
    <INFO>
        <CORP_ID>%s</CORP_ID>
        <CORP_TIME>%llu</CORP_TIME>
        <NAME>%s</NAME>
        <GROUP>%s</GROUP>
        <CORPORATION>%s</CORPORATION>
        <DEPARTMENT>%s</DEPARTMENT>
        <SEX>%u</SEX>
        <POST>%s</POST>
        <TEL>%s</TEL>
        <MOBILE>%s</MOBILE>
        <EMAIL>%s</EMAIL>
        <SIGN>%s</SIGN>
        <SYS_FACE>%llu</SYS_FACE>
        <USER_FACE id="%llu">%s</USER_FACE>
        <STATUS>%u</STATUS>
        <ACTIVE_SEND>%u</ACTIVE_SEND>
        <ONLINE_POPUP>%u</ONLINE_POPUP>
        <HIDE_IP>%u</HIDE_IP>
        <COLOR_NAME>%u</COLOR_NAME>
        <SORT_NAME>%u</SORT_NAME>
        <DECORATE_NAME>%u</DECORATE_NAME>
    </INFO>
    <NET>
        <FILE_TRAN_TCP_PORT>%u</FILE_TRAN_TCP_PORT>
        <FILE_TRAN_ENET_PORT>%u</FILE_TRAN_ENET_PORT>
        <FOLDER_TRAN_TCP_PORT>%u</FOLDER_TRAN_TCP_PORT>
        <FOLDER_TRAN_ENET_PORT>%u</FOLDER_TRAN_ENET_PORT>
        <FILE_TRAN_TCP_REVERSE_PORT>%u</FILE_TRAN_TCP_REVERSE_PORT>
        <FILE_TRAN_ENET_REVERSE_PORT>%u</FILE_TRAN_ENET_REVERSE_PORT>
        <FOLDER_TRAN_TCP_REVERSE_PORT>%u</FOLDER_TRAN_TCP_REVERSE_PORT>
        <FOLDER_TRAN_ENET_REVERSE_PORT>%u</FOLDER_TRAN_ENET_REVERSE_PORT>
        <LAN_UPDATE_HTTP_PORT>%u</LAN_UPDATE_HTTP_PORT>
    </NET>
</X_HANDSHARK>
```

> [!NOTE]
> **TCP 监听端口功能彻底定性**：
> 上述 XML 中的 `<NET>` 节点直接解释了 `AGENTS.md` 中宿主机监听的所有 TCP 端口：
> * `2440`：`FILE_TRAN_TCP_PORT`（文件直传 TCP 端口）
> * `2441`：`FOLDER_TRAN_TCP_PORT`（文件夹直传 TCP 端口）
> * `2442`：`FILE_SHARE_TCP_PORT`（共享文件访问 TCP 端口）

---

## 6. 端口与协议角色判定总结（全量更新）

| 端口 | 传输层 | 角色与功能 | 协议格式 | 证据帧 / 证据来源 |
| :--- | :--- | :--- | :--- | :--- |
| **9011** | **UDP** | **局域网用户上线广播与应答** | 固定 304B 二进制头（含版本 `#3#4#4`、User ID、实例 GUID、动态 UDP 端口） | `03-sandbox-discovery.pcapng` 帧 #1, #2, #5, #6, #45, #48 等 |
| **2425** | **UDP** | **飞鸽/飞秋 (IPMSG) 兼容广播** | ASCII 文本 `1@shiyeline:...:1:...`，通告上线与昵称 | `03-sandbox-discovery.pcapng` 帧 #3, #4, #51, #52, #121, #122 等 |
| **9012** | **UDP** | **P2P 私有可靠主通道** | 二进制 Request-ACK 机制（心跳 0x85、资料/消息 0x88、状态/回执 0x86） | 全部抓包文件，持续双向通信 |
| **53782 / 62916** | **UDP** | **P2P 动态辅助通信端口** | 二进制协议（9011 报文偏移 0xA5~0xA6 通告此端口），与 9012 协同握手 | `03-sandbox-discovery.pcapng` 帧 #9~#10, #12~#13, #21~#22, #25~#26 |
| **2440** | **TCP** | **文件传输（File Transfer）服务** | 承载大文件点对点高速直传 | 二进制字符串 `FILE_TRAN_TCP_PORT` |
| **2441** | **TCP** | **文件夹传输（Folder Transfer）服务** | 承载文件夹递归传输 | 二进制字符串 `FOLDER_TRAN_TCP_PORT` |
| **2442** | **TCP** | **文件共享（File Share）服务** | 局域网共享文件列表检索与下载 | 二进制字符串 `FILE_SHARE_TCP_PORT` |
| **80** | **TCP** | **官方外部状态上报** | HTTP POST `/api/report.php`（`Host: report.51nwt.com`） | `nwt.pcapng` 帧 #4，返回 404 |

---

### 3.8 原生聊天消息时序与 XML 架构（UDP 9012）

经对 `captures/04-text-message.pcapng` 逆向分析，内网通原生客户端之间的普通文本消息**完全不经过 UDP 2425（飞鸽通道），全程运行在 UDP 9012 上**：

1. **输入状态提醒**：
   - Opcode `0x86`（78 字节），子类型 `0x03f0`（十进制 1008）。
   - 载荷对应 XML 实体 `<X_OPERATE_SEND_INPUT_STATE>`，尾部明文为 `ING>`（`<...TYPING>`）。
2. **文本消息分片传输**：
   - Opcode `0x88`（分片 1/2 1400 字节 + 分片 2/2 175 字节 = 1519 字节载荷）。
   - 内部封装格式：
     - 前 4 字节：`0x000005ef`（十进制 1519，总长度）。
     - 次 4 字节：`0x000003ec`（十进制 1004，消息类型 ID `X_SEND_MSG`）。
     - 消息体 XML 模板：
       ```xml
       <X_SEND_MSG>
           <MSG_ID>%llu</MSG_ID>
           <RECEIPT>1</RECEIPT>
           <MSG>%s</MSG>
           <MSG_TIME>%u</MSG_TIME>
           <OFFLINE>0</OFFLINE>
           <HIDE_RECORD>0</HIDE_RECORD>
       </X_SEND_MSG>
       ```
3. **消息分片确认**：
   - 接收方回送 18 字节 MultiACK。
4. **消息送达回执**：
   - Opcode `0x86`（80 字节），子类型 `0x03ed`（十进制 1005）。
   - 对应 XML 模板 `<X_SEND_MSG_ACK docver="%u"><MSG_ID>%llu</MSG_ID></X_SEND_MSG_ACK>`，尾部明文为 `G_ACK>`。

---

### 3.9 双轨密码体系与算法分流器（汇编确证）

在 `ShiYeLine.exe` 虚拟地址 `0x0085167e` 处，反编译挖掘出官方多算法分流逻辑：

```assembly
0x008516bc: cmp  dword ptr [eax + 0xae0], 5  ; algorithm == 5: "none" (明文直接透传)
0x008516c3: jne  0x85171e
0x00851795: cmp  dword ptr [eax + 0xae0], 2  ; algorithm == 2: "aes" / "rijndael" (AES-CBC 16B 分组)
0x0085179c: jne  0x8518dd
0x008518e3: cmp  dword ptr [eax + 0xae0], 3  ; algorithm == 3: "blowfish" / "blowfishOld" (Blowfish 8B 分组)
```

- **Blowfish 8 字节分组截断特性**：
  在 `04-text-message` 的 1519 字节载荷中，除去 8 字节头后剩余 1511 字节：
  $$1511 = 188 \times 8 + 7$$
  前 188 个分组（1504 字节）被 Blowfish 完全加密（出现高频相同密文块，如 `eiSa`、`xq[` 等），而未凑整的最后 7 个字节未经加密直接明文附加在尾部，正是 `</X_SEND_MSG>` 标签的最后 7 个字符：`ND_MSG>`！
- **密钥与 IV 派生（`0x0085d080`）**：
  由通信双方的 User ID 字典序配对后，串联固定盐值并通过 MD5/SHA-1 派生对称密钥与 IV。

---

## 6. 端口与协议角色判定总结（全量更新）

| 端口 | 传输层 | 角色与功能 | 协议格式 | 证据帧 / 证据来源 |
| :--- | :--- | :--- | :--- | :--- |
| **9011** | **UDP** | **局域网用户上线广播与应答** | 固定 304B 二进制头（含版本 `#3#4#4`、User ID、实例 GUID、动态 UDP 端口） | `03-sandbox-discovery.pcapng` 帧 #1, #2, #5, #6, #45, #48 等 |
| **2425** | **UDP** | **飞鸽/飞秋 (IPMSG) 兼容广播** | ASCII 文本 `1@shiyeline:...:1:...`，通告上线与昵称（收到带 `@shiyeline` 报文时主动丢弃，避免产生重复的飞鸽联系人） | `ShiYeLine.exe` `0x005b316d` 汇编确证 |
| **9012** | **UDP** | **P2P 私有可靠主通道** | 二进制 Request-ACK 机制（心跳 0x85、资料/消息 0x88、状态/回执 0x86） | 全部抓包文件，持续双向通信 |
| **53782 / 62916** | **UDP** | **P2P 动态辅助通信端口** | 二进制协议（9011 报文偏移 0xA5~0xA6 通告此端口），与 9012 协同握手 | `03-sandbox-discovery.pcapng` 帧 #9~#10, #12~#13, #21~#22, #25~#26 |
| **2440** | **TCP** | **文件传输（File Transfer）服务** | 承载大文件点对点高速直传 | 二进制字符串 `FILE_TRAN_TCP_PORT` |
| **2441** | **TCP** | **文件夹传输（Folder Transfer）服务** | 承载文件夹递归传输 | 二进制字符串 `FOLDER_TRAN_TCP_PORT` |
| **2442** | **TCP** | **文件共享（File Share）服务** | 局域网共享文件列表检索与下载 | 二进制字符串 `FILE_SHARE_TCP_PORT` |
| **80** | **TCP** | **官方外部状态上报** | HTTP POST `/api/report.php`（`Host: report.51nwt.com`） | `nwt.pcapng` 帧 #4，返回 404 |

---

## 7. 逆向工程成果与演进状态

### 已彻底解决
1. **用户搜索与发现端口（9011）报文格式**：304 字节固定结构已全字段逆向定型，包括动态端口位置。
2. **IPMSG 与原生内网通双轨隔离机制**：确证 `@shiyeline` 标记在 2425 上的过滤作用，明确原生联系人创建依赖 9011/9012/DynPort 7 阶段握手。
3. **初次握手时序生命周期**：从 9011 广播 -> 9012 与动态端口双通道同步 -> Stage 5 `<X_HANDSHARK>` 资料同步 -> 共享凭据锁定 7 个阶段全部理清。
4. **原生聊天报文通道定性**：确证文本消息运行于 UDP 9012，通过 Opcode 0x88 分片封包，根标签为 `<X_SEND_MSG>`。
5. **密码引擎底层定型**：确证 `0x0085167e` 算法分流器（`none` / `aes` / `blowfish`），并完成基于 PyCryptodome 的 `crypto_engine.py` 实现。
6. **图片/微文件 (Mini-File) TCP 传输协议**：完全逆向确证图片在原生客户端间的点对点 TCP 传输协议（Command 1/2/3 格式与 `CLanFileTran::DoDownTask` 状态机），并经 `05-image-transfer.pcapng` 真实抓包校验。

---

## 8. 微文件与图片点对点传输协议（Mini-File TCP Protocol）

### 8.1 传输机制与生命周期
内网通原生客户端在聊天中发送的图片、截图、自定义表情等微文件，并不通过 UDP 9012 直接传输数据载荷，而是采用 **“UDP 元数据通告 + TCP 点对点拉取”** 的分层设计：

1. **UDP 元数据通告**：发送方在 UDP 9012 的 `<X_SEND_MSG>` 报文中嵌入图片元数据（JSON 格式）：
   ```json
   {
       "app": "shiyeline",
       "dt": [
           {
               "img": {
                   "t": "feihu",
                   "v": "{token}|{md5_hex}"
               }
           }
       ],
       "ver": "6.0"
   }
   ```
2. **TCP 端口协商**：接收方根据握手阶段 `<X_HANDSHARK><NET><FILE_TRAN_TCP_PORT>` 记录的发送方 TCP 端口（或本地动态端口），发起 TCP 主动连接。
3. **TCP 请求与应答**：
   - 接收方发送 **Command 1 (Download Request)**，指定目标图片的 MD5 哈希。
   - 发送方返回 **Command 2 (Download Response)**，确认文件存在并通告文件总字节数。
   - 发送方分块发送 **Command 3 (Data Chunk)**（典型块大小 16KB）。
4. **接收端完整性校验**：接收端接收完毕后，调用 `0x594fc0` 计算本地落地文件的 MD5，并与请求的 MD5 执行 `_stricmp` 匹配。匹配成功后通知 UI 渲染图片，并关闭/重置 TCP 连接。

```text
Sender (Host :13603)                                Receiver (Sandbox :49761)
       |                                                    |
       |<--- TCP SYN ---------------------------------------|
       |---> TCP SYN+ACK -----------------------------------|
       |<--- TCP ACK ---------------------------------------|
       |                                                    |
       |<--- Command 1: Download Request (MD5) -------------|
       |---> Command 2: Download Response (Size, Status=0) -|
       |---> Command 3: Data Chunk 0 (0 ~ 16384) -----------|
       |<--- TCP ACK ---------------------------------------|
       |---> Command 3: Data Chunk 1 (16384 ~ 32768) -------|
       |<--- TCP ACK ---------------------------------------|
       |---> Command 3: Data Chunk N (Final Chunk) ---------|
       |<--- TCP ACK ---------------------------------------|
       |<--- TCP RST+ACK (Task Success / Socket Recycle) ---|
```

### 8.2 二进制报文格式剖析

所有 Mini-File 报文均具有固定的 12 字节外层头部：

| 偏移（Offset） | 长度（Bytes） | 字节序 | 字段名 | 说明 |
| :--- | :--- | :--- | :--- | :--- |
| `0x00 ~ 0x03` | 4 | Big Endian | `total_len` | 整个报文总长度（含此 12 字节头部） |
| `0x04 ~ 0x07` | 4 | Big Endian | `proto_type` | 固定为 `0x00000001`（Mini-File 协议标识） |
| `0x08 ~ 0x0B` | 4 | Big Endian | `cmd_id` | 命令 ID（`1`: 请求, `2`: 响应, `3`: 数据块） |

#### 1. Command 1：下载请求报文（Download Request，344 字节 / 500 字节）
- **汇编构造函数**：`ShiYeLine.exe` `0x005aa5c0`
- **字段布局**：
  - `0x00 ~ 0x0B`：基础头部（`cmd_id = 1`）。
  - `0x70 ~ 0x8F`：目标文件的 32 字节 MD5 十六进制字符串（或在聊天场景中内嵌 `{"v": "{token}|{md5}"}` 的 JSON 字符串）。

#### 2. Command 2：下载响应报文（Download Response，固定 356 字节）
- **汇编构造函数**：`ShiYeLine.exe` `0x005aa6e0`
- **字段布局**：
  - `0x00 ~ 0x0B`：基础头部（`cmd_id = 2`，`total_len = 356`）。
  - `0x70 ~ 0x73`：`status`（4 字节 Big Endian，`0` 表示成功/文件就绪，非 0 为错误）。
  - `0x74 ~ 0x93`：`file_md5`（32 字节 ASCII 十六进制小写 MD5 字符串）。
  - `0x94 ~ 0x9B`：`file_size`（8 字节 Big Endian，64 位文件总字节数）。

#### 3. Command 3：数据块分片报文（Data Chunk，长度 = `ChunkLen + 0x98`）
- **汇编构造函数**：`ShiYeLine.exe` `0x005aa820`
- **字段布局**：
  - `0x00 ~ 0x0B`：基础头部（`cmd_id = 3`，`total_len = ChunkLen + 152`）。
  - `0x70 ~ 0x77`：`file_size`（8 字节 Big Endian，64 位文件总字节数）。
  - `0x78 ~ 0x7F`：`file_offset`（8 字节 Big Endian，64 位当前分块起始偏移量）。
  - `0x80 ~ 0x83`：`chunk_len`（4 字节 Big Endian，当前分块数据有效载荷长度）。
  - `0x98 ~ ...`：`chunk_data`（原始二进制数据，长度等于 `chunk_len`）。

### 8.3 接收端核心状态机与校验逆向
在 `ShiYeLine.exe` 中，接收端处理流程完全位于 `CLanFileTran::DoDownTask`（`0x005a44b0` / `0x005a4aa3`）：

1. **响应解析**（`0x005a4c19`）：检查 `status == 0`，调用 `0x005927d0` 将 `0x94` 处的 64 位大端字节序转换为本地整数，并调用 `CreateFileA` 创建临时缓存文件。
2. **分块写入**（`0x005a4d3a`）：从 Command 3 中解出 `chunk_len = ntohl([edi + 0x80])`，直接调用 Win32 `WriteFile` 将 `[edi + 0x98]` 写入磁盘文件，并累加当前已接收字节数 `[ebp + 0x58]`。
3. **完成与 MD5 校验**（`0x00594fc0`）：当累加字节数达到总大小时，调用 `0x00594db0` 计算下载文件的磁盘 MD5，通过 `_stricmp` 与预期 MD5 对比。匹配后通知 UI 显示并复位连接。

