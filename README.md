# RevAgent — 基于 MCP 协议的"动静结合"AI 逆向分析 Agent

> 让 LLM 像人类逆向工程师一样思考：先跑起来看行为，再有目的地读代码。

RevAgent 通过 [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) 将 **Ghidra 静态反编译**与 **GDB/pwntools 动态调试**统一编排，配合自研 Agent 行为规训方法论，实现从二进制文件到逆向结论的端到端自动化分析。

## 为什么需要 RevAgent？

现有的 AI 辅助逆向工具大多停留在"把反编译代码丢给 LLM 让它解释"的阶段。这在简单场景下有效，但面对真实的高难度样本时会迅速碰壁：

- **反编译不等于理解**：Rust/C++ 内联后的巨型函数动辄上万行伪 C 代码，LLM 读了也是幻觉
- **静态分析有盲区**：反调试、自修改代码、运行时生成密钥等场景，不跑起来永远看不到真相
- **LLM 会陷入死循环**：没有约束的 Agent 会反复尝试同一条失败路径，耗尽 Context Window

RevAgent 的解法是**动静结合 + 行为规训**：让 Agent 在静态分析遇到瓶颈时自动切换到动态调试，同时通过方法论框架约束 Agent 的推理路径，避免幻觉和无效循环。

## 架构

```
┌─────────────────────────────────────────────────┐
│              LLM (Claude / 任意模型)              │
│         + CLAUDE.md 行为规训方法论 (v2)            │
└──────────┬──────────────────┬────────────────────┘
           │ MCP (stdio)      │ MCP (stdio over SSH)
           ▼                  ▼
┌─────────────────┐  ┌──────────────────────────────┐
│   静态分析端     │  │        动态分析端              │
│  (Windows)      │  │    (Kali VM - 隔离环境)        │
│                 │  │                                │
│  GhidraMCP      │  │  dynamic_mcp_server.py v0.3   │
│  (开源插件)      │  │  ├─ run_dynamic_trace          │
│  163 tools      │  │  ├─ gdb_breakpoint_read        │
│  + 自定义扩展    │  │  │  (5类断点 + watchpoint       │
│                 │  │  │   + extra_commands + bt)     │
│  交叉引用追踪    │  │  └─ disassemble_bytes          │
│  内存批量读取    │  │                                │
│  字符串/全局搜索  │  │  特性:                         │
│                 │  │  · asyncio + 线程池并发         │
│                 │  │  · 参数化接口 (防注入)           │
│                 │  │  · 超时熔断                     │
│                 │  │  · 环境变量注入                  │
│                 │  │  · 反调试绕过                    │
└─────────────────┘  └──────────────────────────────┘
```

**为什么是 MCP 而不是 Function Calling / LangChain？**

- **跨机器解耦**：静态端在 Windows（Ghidra），动态端在 Kali VM，MCP 天然支持 stdio / SSE 两种传输，无需自造 RPC
- **工具规模**：163 个静态分析工具 + 动态调试工具，MCP 的 tool schema 支持模型自主发现和选择
- **模型无关**：换模型不需要改工具层，只需替换 MCP Client

## Agent 行为规训方法论 (CLAUDE.md)

这是 RevAgent 的核心竞争力——不是工具多，而是 **Agent 知道什么时候该用哪个工具、什么时候该停下来**。

### 核心原则：动态优先

> 任何题目，在做超过 5 分钟的静态分析之前，必须先动态运行程序观察行为。

静态反编译可能 misleading，但程序的实际交互行为不会骗你。

### 九类强制规则

| 规则 | 内容 | 解决的问题 |
|------|------|-----------|
| **规则 0** | 先跑起来看看 | 避免盲目静态分析 |
| **规则 1** | 开题三步曲：追溯入口点 → 搜索关键字符串 → 输出攻击计划 | 建立结构化分析流程 |
| **规则 2** | 交叉引用是核心手段 | 低成本高收益的分析路径 |
| **规则 3** | 不信任函数名称 | 防止自定义函数伪装（如自定义 `puts` 中藏反调试） |
| **规则 4** | 禁止在 thinking 中做密集计算 | 强制使用脚本，避免 LLM 幻觉计算 |
| **规则 5** | 全局变量多处修改 → 动态读取 | 避免静态分析遗漏运行时修改 |
| **规则 6** | 每步行动后立刻产出 | 保持分析节奏，防止 thinking 卡顿 |
| **规则 7** | 巨型函数不反编译 | 防止 Context Window 溢出 |
| **规则 8** | 实验科学模式：dump 数据 > 读代码 | 从数据归纳模式比从汇编归纳容易一个数量级 |

### 三级熔断机制

```
时间熔断：单步 thinking > 3 min → 写 Python 脚本
          单题总耗时 > 20 min → 暂停，输出进度摘要

方向熔断：同类输入连续 3 次失败 → 切换到 GDB 断点分析
          同一函数看 3 页无结论 → 切换动态分析
          追踪进入标准库内部 → 立刻停止

深度熔断：调用链 > 5 层未找到用户逻辑 → GDB I/O 断点直接观察
          所有输入返回错误 → 断点分析输入解析函数
```

### Context 裁剪策略

LLM 的 Context Window 是稀缺资源。RevAgent 的策略是**让 Agent 做检索，而不是做阅读**：

- 不反编译整个 binary，通过字符串 xrefs 定位关键路径
- 超过 5000 条指令的函数，用 `CALL` 过滤只提取调用点
- 动态 dump 代替静态通读——把运行时数据喂给 LLM，而不是让它读汇编

本质上这是一个 **RAG 思路**：二进制是知识库，tool call 是检索，Context 里只放当前推理需要的片段。

## 安全设计

### 执行隔离

所有动态分析在 **隔离 Kali VM** 中执行，宿主机通过 SSH 隧道通信。目标二进制的任何行为（网络、文件系统、进程）均被限制在 VM 内，快照可随时回滚。

### 命令安全

Agent 生成的调试指令通过 **参数化接口** 执行（如 `gdb_breakpoint_read` 接受结构化参数），Server 端负责拼装合法 GDB 命令，避免命令注入。每次执行有 timeout 强制终止。

### 并发模型

```
asyncio event loop (主循环，处理 MCP 消息)
    │
    ├─ LLM 推理 (流式，非阻塞)
    │
    └─ ThreadPoolExecutor
         ├─ GDB 会话 (阻塞调用，run_in_executor 隔离)
         ├─ pwntools 交互 (阻塞调用)
         └─ 子进程执行 (timeout 控制)
```

## 已验证样本

| 样本 | 难度 | 技术特征 | 结果 | 工具调用次数 |
|------|------|---------|------|------------|
| simp-password | ★☆☆ | 明文字符串比较 | ✅ 全自动 | ~4 |
| requiem | ★★☆ | Stripped Rust, XOR 加密 | ✅ 全自动 | ~10 |
| tomb (500pt) | ★★★ | 多层 XOR + 自定义 puts 反调试 + shellcode | ✅ 半自动 (4次人工) | ~30 |
| bedtime (DiceCTF) | ★★★★ | 巨型 Rust 二进制, 博弈引擎, PRNG | 🔄 分析阶段 | — |

## 快速开始

### 前置条件

- [Ghidra](https://ghidra-sre.org/) 12.0+ 及 [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) 插件
- Kali Linux VM（推荐 Proxmox/VMware，需 SSH 访问）
- Python 3.10+, `pwntools`, `gdb`
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) 或任意支持 MCP 的 LLM Client

### 安装

```bash
# 1. 静态端：安装 GhidraMCP 插件（按官方文档）
# 在 Ghidra 中: File → Install Extensions → 选择 GhidraMCP.zip

# 2. 动态端：部署到 Kali VM
scp dynamic_mcp_server.py kali@<VM_IP>:/home/kali/lab/
ssh kali@<VM_IP>
pip install pwntools mcp-server

# 3. 配置 MCP Client（以 Claude Code 为例）
# 编辑 .claude.json，添加两个 MCP Server：
```

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "command": "python",
      "args": ["bridge_mcp_ghidra.py"],
      "transport": "stdio"
    },
    "pwntools-dynamic": {
      "command": "ssh",
      "args": ["kali@<VM_IP>", "python3", "/home/kali/lab/dynamic_mcp_server.py"],
      "transport": "stdio"
    }
  }
}
```

### 使用

```bash
# 1. 启动 Ghidra，加载目标二进制，启动 GhidraMCP Server
# 2. 将目标二进制复制到 Kali VM
# 3. 启动 Claude Code
claude --dangerously-skip-permissions

# 4. 验证 MCP 连接
/mcp  # 确认两端 ✓ Connected

# 5. 开始分析
> 请分析 /home/kali/lab/target_binary，找出 flag
```

## 项目结构

```
RevAgent/
├── README.md
├── CLAUDE.md                    # Agent 行为规训方法论 v2
├── dynamic_mcp_server.py        # 动态分析 MCP Server (核心)
├── bridge_mcp_ghidra.py         # Ghidra MCP 桥接层
├── docs/
│   ├── CHANGELOG.md             # 开发日志
│   └── PROJECT_CONTEXT.md       # 架构与能力边界
└── benchmarks/                  # 验证样本与测试结果
    └── results.json
```

## Roadmap

- [x] Phase 1：基础设施搭建（Ghidra MCP + 动态 MCP Server v0.3）
- [x] CLAUDE.md v2：九类规则 + 三级熔断 + 实验科学模式
- [ ] pwntools 断连检测与自动重连
- [ ] `gdb_breakpoint_read` 增加 `stdin_data` 和 `continue_count` 参数
- [ ] 自动计算 PIE base address
- [ ] Agent 策略迭代：程序类型自动分类、输入格式探测流程
- [ ] `patch_binary` / `run_interactive_script` 工具
- [ ] Benchmark：10-20 题自动化评估
- [ ] 技术 Blog

## 致谢

- [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) — 开源 Ghidra MCP 插件，本项目静态端的基础
- [Model Context Protocol](https://modelcontextprotocol.io/) — Anthropic 开源的工具调用协议

## License

MIT
