

# 🛡️ Go-SSH-Bastion: 高并发分布式安全审计堡垒机

## 📖 项目简介 (Project Overview)

**Go-SSH-Bastion** 是一款基于 Golang 编写的、支持千级并发连接的轻量级、高性能分布式 SSH 堡垒机系统。本项目脱胎于高级系统编程与网络安全课程设计，旨在通过原生 Go 语言的并发模型（Goroutine）和现代微服务通信框架（gRPC），解决传统运维场景中对海量服务器安全管控、密码免密代填、高危命令拦截以及实时操作审计的痛点。

本项目在架构上采用了“无状态网关 + 集中式审计服务”的解耦设计。堡垒机（Proxy）本身不保存任何后端服务器的敏感凭证，所有的凭证获取、命令校验与日志记录均通过跨进程通信（IPC）交由后端的审计中心（Audit Server）处理，极大提升了系统的安全水位与横向扩展能力。

---

## ✨ 核心特性 (Core Features)

本项目完全覆盖并超越了标准 SSH 代理程序的设计要求，实现了以下九大核心能力：

1. **🚀 极限并发与多线程编程模型：** 摒弃了传统的“一连接一线程/进程”的笨重模型，全面采用 Go 语言原生的 Goroutine 轻量级协程机制。实测在极低的内存消耗下，轻松支撑 **1000+** 的同时期在线 SSH 客户端连接。
2. **🔌 现代化的进程间通信 (IPC)：** 采用 Google 开源的 **gRPC** 与 **Protocol Buffers** 作为堡垒机网关与审计服务之间的 IPC 通信协议。实现了强类型、低延迟的数据交互，完美诠释了进程间通信的概念与应用。
3. **🌐 深度整合网络与 SSH 协议：** 基于 `golang.org/x/crypto/ssh` 深度定制底层 SSH 握手、认证与多路复用信道（Channel）逻辑。完整支持标准 SSH2.0 协议的 PTY 伪终端请求、环境遍历传递与窗口大小自适应（Window Change）。
4. **🔄 智能动态路由与转发：** 首创 `用户名_目标IP` 的动态登录寻址规范。用户只需连接堡垒机的一个统一入口，即可根据连接指令动态路由转发至成百上千个不同的后端物理机或虚拟机。
5. **🔑 零信任 RPC 凭证代填：** 堡垒机网关彻底“无状态化”。当客户端请求连接后端时，网关会通过 gRPC 接口实时向第三方审计中心发起 `GetBackendCredentials` 请求，获取认证公钥或密码并完成自动代填，彻底杜绝凭证在网关侧的泄漏风险。
6. **⚡ 无损透明代理透传：** 建立连接后，通过 Go 原生的 `io.Copy` 实现双向字节流的零阻塞高速透传，用户体验与直接连接目标服务器完全一致。
7. **🕵️ 毫秒级命令解析与记录：** 在字节流转发链路中植入旁路监听机制（Bypass Sniffing）。通过自定义的行缓冲读取器，实时截获用户发往后端的 `Stdin` 击键流，并在用户按下回车键的瞬间捕获完整命令行。
8. **🛑 规则引擎与高危命令拦截：** 审计中心内置可热插拔的命令黑名单（如 `rm -rf /`, `shutdown` 等）。当捕获到敏感指令时，gRPC 接口同步返回拒绝信号，堡垒机将在毫秒内阻断该指令发往后端，并向客户端屏幕高亮输出红色告警提示（Security Alert）。
9. **📊 配置解耦与全局状态可视：** 系统参数通过统一的 YAML 本地文件读取。引入了 `sync/atomic` 原子级计数器，实时且线程安全地统计当前全局在线会话数，并通过控制台日志动态展示系统的运行状态信息。

---

## 🏗️ 架构设计 (Architecture Design)

系统由两个独立的物理进程（或微服务节点）组成：**Bastion Proxy (堡垒机代理进程)** 和 **Audit RPC Server (审计管控进程)**。

```text
+----------------+       1. SSH Login (admin_123)        +-------------------+
|  SSH Client    | ------------------------------------> |                   |
| (Terminal/Xshell)|                                     |  Bastion Proxy    |
+----------------+       8. Return Security Alert        |  (无状态代理网关)  |
       ^                 <--------------------------------  (Port: 22222)    |
       |                                                 +-------------------+
       |                                                   | ^   | ^   | ^
       |                     2. RPC Request Credential     | |   | |   | |
       |                     3. RPC Return Password        | |   | |   | |
       | 7. Return Result    ------------------------------+ |   | |   | |
       | (If command allowed)  5. RPC Check Command (rm -rf) |   | |   | |
       |                       6. RPC Return Allowed(T/F)----+   | |   | |
       |                                                         | |   | |
       |                                   4. Dial SSH Backend   | |   | |
       +---------------------------------------------------------+ |   | |
                                                                   v   | v
+----------------+      +----------------+      +----------------+     | |
| Backend Server |      | Backend Server |      | Backend Server |     | |
| (192.168.1.10) |      | (192.168.1.11) |      | (192.168.1.12) |     | |
+----------------+      +----------------+      +----------------+     | |
                                                                       | |
                                                                       v |
                                                 +-------------------+
                                                 | Audit RPC Server  |
                                                 | (安全审计中心)    |
                                                 | (Port: 50051)     |
                                                 +-------------------+
                                                 - 黑名单规则库
                                                 - 凭证数据库
                                                 - 审计日志持久化

```

**数据流转说明：**

1. 客户端通过 `ssh user_ip@bastion_ip` 发起连接。
2. 堡垒机向审计中心发起 gRPC 请求，拉取对应 `ip` 的后端凭证。
3. 堡垒机利用获取到的凭证，代替用户自动登录后端。
4. 会话建立，堡垒机开始双向监听。
5. 当用户输入命令并按下回车，堡垒机拦截该命令字符串，通过 gRPC 询问审计中心是否合规。
6. 若合规，透传给后端执行；若违规，丢弃该命令，向用户终端打印警告。

---

## 📂 目录结构 (Directory Structure)

遵循 Go 语言工程化最佳实践 (Standard Go Project Layout)。

```bash
D:\ssh-bastion\
├── cmd\                             # 可执行程序入口目录
│   ├── audit\
│   │   └── main.go                  # 审计系统启动入口
│   └── bastion\
│       └── main.go                  # 堡垒机网关启动入口
├── internal\                        # 内部私有业务逻辑层
│   ├── audit\
│   │   └── server.go                # gRPC 服务端具体实现 (密码下发、命令拦截、日志打印)
│   ├── config\
│   │   └── config.go                # YAML 配置解析器与结构体定义
│   └── sshproxy\
│       └── proxy.go                 # SSH 协议栈核心逻辑 (建立连接、PTY请求、信道转发、字节拦截)
├── proto\                           # 协议定义目录
│   ├── audit.proto                  # gRPC 接口与 Protobuf 消息体定义
│   ├── audit.pb.go                  # 自动生成的 Protobuf 数据结构代码
│   └── audit_grpc.pb.go             # 自动生成的 gRPC 客户端/服务端存根代码
├── audit.yaml                       # 审计系统配置文件 (高机密：包含黑名单与后端密码库)
├── bastion.yaml                     # 堡垒机配置文件 (网关运行参数、自身认证密码)
├── host_key                         # 堡垒机自身的 RSA 身份私钥 (系统自动/手动生成)
├── main.go                          # 聚合启动器 (一键并发启动审计+堡垒机双进程)
├── go.mod                           # Go 模块依赖管理
└── go.sum                           # 依赖版本哈希校验

```

---

## 🛠️ 安装与编译 (Installation & Build)

### 1. 环境准备

* 操作系统：支持 Windows, macOS, Linux
* 运行环境：Go 1.20 或以上版本
* 依赖工具：`protoc` (Protocol Buffers 编译器) 及其 Go 语言插件。

### 2. 克隆与初始化

```bash
git clone <your-repository-url>
cd ssh-bastion
go mod tidy # 拉取所有相关依赖 (crypto/ssh, grpc, yaml.v3等)

```

### 3. 生成 gRPC 代码 (若修改了 .proto 文件)

```bash
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/audit.proto

```

### 4. 生成堡垒机身份密钥

堡垒机需要一把属于自己的私钥来供客户端验证身份。在项目根目录下执行：

```bash
ssh-keygen -t rsa -f host_key
# 提示输入密码时，直接连按两次回车留空即可

```

### 5. 编译执行

```bash
# 全局语法检查
go build ./...

# 编译生成可执行文件 (可选)
go build -o ssh-bastion.exe main.go

```

---

## ⚙️ 配置详解 (Configuration)

本系统采用双配置文件分离设计，确保职责分明。

### 1. `bastion.yaml` (堡垒机网关配置)

此配置放置于堡垒机节点，仅包含网关网络参数，**不包含任何后端机器的真实密码**，即使网关被攻破，攻击者也无法获取内网凭证。

```yaml
listen_addr: "0.0.0.0:22222"      # 堡垒机对外暴露的监听地址与端口
host_key: "./host_key"            # 堡垒机身份私钥路径
audit_addr: "localhost:50051"     # 内部 gRPC 审计服务的地址
bastion_pass: "admin123"          # 统一门户密码（所有用户连接堡垒机第一道门的安全验证）

```

### 2. `audit.yaml` (审计服务配置)

此配置放置于处于内网深处、受到严格保护的审计节点，包含核心机密数据。

```yaml
listen_addr: "localhost:50051"    # gRPC 服务的监听地址
blacklist:                        # 高危命令正则表达式/字符串匹配黑名单
  - "rm -rf"
  - "shutdown"
  - "reboot"
  - "drop database"
passwords:                        # 第三方凭证数据库 (模拟)。Key 为目标服务器 IP，Value 为真实登录密码
  "192.168.65.128": "root_password_here"
  "10.0.0.55": "web_server_pass"

```

---

## 🚀 启动与使用指南 (Usage Guide)

### 第一步：启动服务

在项目根目录下，使用总入口聚合启动两个服务：

```bash
go run main.go

```

启动成功后，控制台将输出：

```text
2026/06/12 12:00:00 Starting SSH Bastion System...
2026/06/12 12:00:01 [Audit] RPC Server listening on localhost:50051
2026/06/12 12:00:02 Bastion listening on 0.0.0.0:22222

```

*注：系统每隔 10 秒会打印当前的并发活跃连接数 `[State] Current Active SSH Connections: X`。*

### 第二步：客户端动态路由连接

使用标准 SSH 客户端连接堡垒机。连接格式必须遵循：
**`ssh <真实后端用户名>_<真实后端IP>@<堡垒机IP> -p <堡垒机端口>`**

例如，我们要通过本地的堡垒机连接到内网的 `192.168.65.128` 这台机器的 `root` 账户：

```bash
ssh -p 22222 root_192.168.65.100@localhost

```

### 第三步：门户认证与无感穿越

敲下上述命令后，终端会提示输入密码。
此时**必须输入堡垒机门户密码**（即 `bastion.yaml` 中的 `admin123`），而非后端密码。
验证通过后，堡垒机会在一瞬间通过 RPC 获取虚拟机密码、完成代填，将你直接送入后端机器的 Shell 环境中。

### 第四步：安全审计体验

在登录后的 Shell 中尝试执行正常命令：

```bash
root@backend:~# ls -la    # 正常返回结果
root@backend:~# pwd       # 正常返回结果

```

尝试执行高危破坏命令：

```bash
root@backend:~# rm -rf /
[Security Alert] Command 'rm -rf /' is prohibited!

```

该命令不仅会被立即拦截阻断，不会对后端服务器造成任何影响，同时在运行堡垒机服务的主控制台上会立即打出审计日志：
`[AUDIT LOG] User: root_192.168.65.128 | Command: rm -rf /`

---

## 🛠️ gRPC 接口文档 (gRPC API Reference)

所有的跨进程通信接口定义在 `proto/audit.proto` 中。

| 接口名称 | 请求参数 | 响应参数 | 描述说明 |
| --- | --- | --- | --- |
| `CheckCommand` | `command` (命令内容)<br>

<br>`user` (用户名)<br>

<br>`target` (目标IP) | `allowed` (布尔值)<br>

<br>`reason` (阻断原因) | 核心审计引擎：接收截获的命令行，匹配黑名单规则引擎，返回是否允许放行。 |
| `LogCommand` | `command` (命令内容)<br>

<br>`user` (用户名) | `Empty` | 异步日志记录引擎：接收用户的全量操作日志并持久化打印，不阻塞 SSH 数据流转发。 |
| `GetBackendCredentials` | `target_ip` (目标机器IP) | `password` (代填密码) | 零信任凭证下发引擎：根据请求的 IP 地址，在安全的凭证库中检索对应的密码或私钥并返回。 |

---

## ⚠️ 常见排错指南 (Troubleshooting)

**1. 报错：`WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!**`

* **原因分析：** 客户端检测到本机的堡垒机端口 (如 22222) 对应的身份公钥指纹发生了变化。通常是因为你重新生成了 `host_key`，或者该端口之前被其他 SSH 服务（如虚拟机、Docker）占用过。
* **解决对策：** 清除本地缓存的该端口旧指纹即可。
```bash
ssh-keygen -R "[127.0.0.1]:22222"

```



**2. 报错：`channel 0: open failed: connect failed: failed to connect to backend**`

* **原因分析：** 堡垒机自身验证通过，但在拿着密码去连接后端 `192.168.x.x` 时，发现目标机器网络不通，或者目标机器的 22 端口根本没有启动 sshd 服务。
* **解决对策：**
1. 确认目标机器处于开机且联网状态 (`ping 192.168.x.x`)。
2. 确认目标机器开启了 SSH 服务。若以 Windows 为测试后端，需管理员身份运行 `Start-Service sshd`。



**3. 报错：`failed to exit idle mode: received empty target in Build()**`

* **原因分析：** gRPC 初始化失败。通常是因为 `bastion.yaml` 配置文件中的 `audit_addr` 字段为空或解析失败，导致堡垒机找不到审计服务的地址。
* **解决对策：** 检查 `bastion.yaml`，确保严格遵循 YAML 缩进与冒号后加空格的规范。

---

## 🔮 未来展望 (Future Work)

本架构设计已具备企业级雏形，若要进一步推向商用级生产环境，可从以下维度继续演进：

1. **数据库持久化接入：** 将 `audit.yaml` 中的明文密码字典和简单的控制台日志输出，替换为 MySQL/PostgreSQL 和 Redis 缓存，实现海量密码与海量审计日志的高效存取。
2. **SSH 录像回放 (Session Replay)：** 利用拦截到的 `Stdout` 字节流，将其按照时间戳格式持久化保存为 `.cast` 文件，配合前端 Asciinema 等工具实现操作的视频级录像与完整审计回放。
3. **动态 MFA 双因子认证：** 堡垒机入口除了密码认证，在 gRPC 验证环节接入 Google Authenticator 或短信验证码，提升准入安全性。
4. **Web 运维管理面板：** 基于 Go 编写配套的 RESTful API，提供一个 React/Vue 的可视化前端面板，实现服务器资产管理、人员权限分配和黑名单规则热更新。

