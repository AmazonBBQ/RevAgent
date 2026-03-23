# Project RevAgent — 完整上下文同步文档
**日期：2026-03-22**
**版本：v0.4（tomb 成功 + bedtime 失败 复盘后）**

---

## 一、项目定位

**一句话描述**：基于 MCP 协议的"动静结合" AI 逆向分析 Agent，将 Ghidra 静态分析 + GDB/pwntools 动态执行统一编排，辅助/自动化 CTF Reverse 解题。

**核心差异化**：市面上没有开源方案同时接了 Ghidra（163 tools）+ GDB 断点/watchpoint + pwntools 执行给 AI Agent 用。MCP 协议使得工具链与模型解耦，可对接任何 MCP 客户端。

---

## 二、经过 5 道题验证的成熟度评估

| 题目 | 难度 | 结果 | 人工干预 | 关键瓶颈 | 动态端价值 |
|------|------|------|---------|---------|-----------|
| simp-password | Easy | ✅ 全自动 | 0 次 | 无 | 低（验证） |
| requiem | Medium | ✅ 全自动 | 0 次 | 无 | 低（验证） |
| tomb | Hard (500pt) | ✅ 半自动 | 4 次 | 反调试识别 | **极高** |
| bedtime | Hard (DiceCTF) | ❌ 分析阶段 | 2 次 | 语义理解 | 未充分使用 |

### 验证的假设

- **假设1 "Hard 题需要动静结合"** → ✅ tomb 完美验证
- **假设2 "LLM 能理解反编译伪代码"** → ⚠️ 简单-中等逻辑 OK，博弈引擎/巨型函数不行
- **假设3 "结构化输出优于原生 GDB"** → ✅ gdb_breakpoint_read 帮助发现 tomb_key 每次不同

### 系统能力边界（当前）

| 能力 | 状态 | 说明 |
|------|------|------|
| 明文比较 (strcmp) | ✅ 全自动 | simp-password |
| 固定密钥 XOR | ✅ 全自动 | requiem |
| 多层 XOR + 反调试 | ✅ 半自动 | tomb（需人类指导反调试层） |
| SHA256 查表逆向 | ✅ 半自动 | tomb lock table |
| 自解密 shellcode | ✅ 半自动 | tomb（disassemble_bytes + Python 重放） |
| 博弈引擎识别 | ❌ | bedtime（无法从代码识别 Nim） |
| 巨型 main 分析 (>10K 指令) | ❌ | bedtime（Rust 内联导致反编译失败） |
| PRNG 状态追踪 | ❌ | bedtime（需 hardware watchpoint 发现 state[2] 更新规则） |
| VM/字节码解释器 | 未测试 | 计划用 pwn.college 测试 |

---

## 三、系统架构

```
┌──────────────────────────────────────────────────┐
│              Agent Router (大脑)                  │
│         Claude Code CLI v2.1.81                  │
│         Sonnet 4.6 (Pro 默认)                    │
│         CLAUDE.md 方法论 v2                      │
└──────────┬────────────────────┬───────────────────┘
           │ MCP (stdio)        │ MCP (stdio over SSH)
           ▼                    ▼
┌─────────────────┐  ┌─────────────────────────────┐
│ 左手-静态感知端 │  │ 右手-动态验证端             │
│ Ghidra MCP      │  │ Pwntools MCP Server v0.3    │
│ Bridge (Python) │  │                              │
│ 163 tools       │  │ Tools:                       │
│ ↕ HTTP :8089    │  │ - run_dynamic_trace (+env)   │
│ Ghidra 12.0     │  │ - gdb_breakpoint_read        │
│ + GhidraMCP     │  │   (5种断点 + extra_commands  │
│   Plugin v4.3.0 │  │    + backtrace)              │
│                 │  │ - disassemble_bytes           │
│ [Windows 物理机]│  │                              │
│                 │  │ [Kali VM 192.168.239.129]    │
└─────────────────┘  └─────────────────────────────┘
```

### 物理部署

| 组件 | 位置 | 路径 |
|------|------|------|
| Claude Code | Windows | 从 `C:\Users\Chen\Desktop\folder` 启动 |
| CLAUDE.md | Windows | `C:\Users\Chen\Desktop\folder\CLAUDE.md` |
| .claude.json | Windows | `C:\Users\Chen\.claude.json` |
| Ghidra 12.0 | Windows | `C:\Tools\ghidra_12.0_PUBLIC` |
| bridge_mcp_ghidra.py | Windows | `C:\Users\Chen\Desktop\ghidra-mcp\` |
| dynamic_mcp_server.py | Kali | `/home/kali/lab/ghidra-ai/dynamic_mcp_server.py`（v0.3） |
| 题目 ELF 文件 | Kali | `/home/kali/lab/ghidra-ai/` |

### MCP 配置 (.claude.json)

```json
{
  "mcpServers": {
    "ghidra-mcp": {
      "type": "stdio",
      "command": "cmd",
      "args": ["/c", "py", "C:\\Users\\Chen\\Desktop\\ghidra-mcp\\bridge_mcp_ghidra.py"],
      "env": { "GHIDRA_SERVER_URL": "http://127.0.0.1:8089/" }
    },
    "pwntools-dynamic": {
      "type": "stdio",
      "command": "ssh",
      "args": ["-o", "StrictHostKeyChecking=no", "kali@192.168.239.129",
               "python3", "/home/kali/lab/ghidra-ai/dynamic_mcp_server.py"]
    }
  }
}
```

---

## 四、题目详细记录

### 题目 3: tomb / Blackbeard's Tomb (BearcatCTF 2026, 500pt) — ✅ 成功

**特征**: Statically linked, not stripped, OpenSSL, 3 层反调试, 自解密 shellcode, RWX segments
**Flag**: `BCCTF{Buri3d_at_sea_Ent0m3d_amm0nG_th3_w4v3S}` (45 字符)
**运行依赖**: `OPENSSL_CONF=/dev/null`

**6 层验证架构**:
```
_start → proc()        [反调试#1: TracerPid, XOR 0x1356 to tomb_key]
  → main()
    → custom puts()    [反调试#2: ptrace TRACEME, XOR pattern to tomb_key]
    → SHA256("BCCTF{") [XOR tomb_key]
    → length check 45  [XOR 0x7D to tomb_key]
    → lock table ×20   [SHA256 pair check, XOR tomb_key]
    → shellcode        [反调试#3: self-decrypting, flag[26+i]=tk[i]^(5i+0x40)]
```

**Agent 表现**:
- ✅ 识别 OpenSSL, SHA256, xor 函数, lock table 逆向查表 (flag[6..26])
- ✅ 发现 tomb_key 每次 GDB 读值不同 → 追查到 proc()
- ❌ 第一次完全没发现 proc() 和自定义 puts()
- ❌ 多次卡在 thinking 中手算 SHA256（6+ 分钟）
- 最终通过 Python 脚本重放 5 层 XOR 成功解出

**关键教训**:
- `gdb_breakpoint_read` 的真正价值：不是直接读正确值，而是暴露"值每次不同"的异常
- GDB 本身可能触发反调试 → 不能盲信 GDB 读出的运行时值
- Python 重放所有 XOR 层是最可靠的方法

### 题目 4: bedtime (DiceCTF 2026, Rev Hard) — ❌ 分析阶段未完成

**特征**: Stripped Rust binary, static-PIE, 13688 条指令的 main, 自定义 PRNG, 384 轮 bounded Nim
**Flag**: `dice{regularly_runs_like_mad_to_game_of_matches}`

**Agent 发现（正确的）**:
- ✅ 入口点追溯: _start → FUN_00127a50 → FUN_0010ab10 (main)
- ✅ main 的复杂度: 880 基本块, 13688 指令, 1203 个 CALL
- ✅ PRNG 常量 0x28027f28b04ccfa7 及其函数 FUN_00128680
- ✅ 9999 哨兵值 (组分隔符)
- ✅ B-tree 结构 (height/edge assertions)
- ✅ 384 轮循环结构 (385 对 print/read)
- ✅ switch 分发表 (~380 个输出分支，flag 字节)
- ✅ 交互模式: "> " 提示 → 读输入 → 验证

**Agent 失败（错误的）**:
- ❌ 认为输入是 /proc/self/maps 格式（实际是 4 位十进制数字）
- ❌ 未识别出 bounded Nim 博弈框架
- ❌ 所有测试输入都返回 "bad"，无法推进
- ❌ 陷入 Rust 标准库内部代码追踪 (mutex, BufRead, allocator)
- ❌ 多次长时间 thinking 卡顿 (10-37 分钟)

**根因分析**:
1. **13688 条指令的 main 无法反编译** → 静态分析严重受阻
2. **输入格式靠猜不靠谱** → 应该用 GDB 在解析函数入口断点分析
3. **博弈引擎的语义识别** → 需要数学洞察（Sprague-Grundy），超出当前模型能力
4. **Rust 标准库干扰** → 大量时间浪费在追踪无关的库代码

**别人怎么解的（writeup 分析）**:
- 人机协作（Claude Opus + 人类）
- GDB Python 脚本运行时 dump 384 组游戏数据（绕过静态分析 main）
- 人类识别 bounded Nim + Sprague-Grundy
- Hardware watchpoint 发现 PRNG state[2] 只受用户 move 影响
- Opus 写了完整的 384 轮模拟器 + 求解脚本

---

## 五、已识别的失败模式与对策

| 失败模式 | 出现频率 | 题目 | CLAUDE.md 对策 |
|---------|---------|------|---------------|
| Thinking 中做密集计算 | 高 (4+次) | tomb | 规则4: 3分钟规则，强制写脚本 |
| 长上下文导致响应变慢 | 每题后期 | tomb, bedtime | 每题开新会话 |
| 未追溯 _start 调用链 | 1 次 | tomb | 规则1: 开题三步曲 |
| 未怀疑同名标准库函数 | 1 次 | tomb | 规则3: 不信任函数名 |
| 巨型函数反编译失败 | 1 次 | bedtime | 规则7: >5000指令用子函数分析 |
| 追踪标准库内部代码 | 多次 | bedtime | 熔断: 检测到 mutex/allocator 立刻停止 |
| 输入格式盲猜 | 多次 | bedtime | 熔断: 3次失败后改用 GDB 断点分析 |
| 不先运行就分析 | bedtime 第一阶段 | bedtime | 规则0: 动态优先 |

---

## 六、技术栈详情

### 动态端 MCP Server (v0.3)

```
Tools:
1. run_dynamic_trace
   - env_vars 支持 (OPENSSL_CONF, LD_PRELOAD 等)
   - 30 秒硬超时
   - 结构化 JSON 返回 (exit_reason, stdout, registers)

2. gdb_breakpoint_read
   - 5 种断点: software, hardware, read_watch, write_watch, access_watch
   - extra_commands: 断点命中后执行自定义 GDB 命令 (如 "set $rax=0")
   - 自动 backtrace (bt 10)
   - 内存区域批量读取

3. disassemble_bytes
   - capstone 反汇编
   - 支持 x86_64, x86, arm, arm64
```

### Claude Code 模型信息

- Pro 订阅默认: **Sonnet 4.6**（不额外收费）
- Opus 4.6 需要 extra usage（按 token 计费）
- Sonnet 4.6 SWE-bench 79.6%, Opus 4.6 80.8%（差 1.2%）
- 对 tomb 的失败不是模型智力问题，是工具缺失 + 策略缺失
- 对 bedtime 的失败部分是模型智力问题（博弈识别需要 Opus 级别推理）
- MCP 协议模型无关，可对接 Claude Code, Cursor, Gemini CLI, Codex CLI 等

---

## 七、启动检查清单

1. 启动 Kali VM: `ssh kali@192.168.239.129 "echo ok"`
2. 启动 Ghidra, 打开目标二进制 (CodeBrowser)
3. Restart MCP Server: Tools → GhidraMCP → Restart Server
4. 验证 HTTP: `curl -UseBasicParsing http://127.0.0.1:8089/check_connection`
5. 启动 Claude Code:
   ```powershell
   cd C:\Users\Chen\Desktop\folder
   claude --dangerously-skip-permissions
   ```
6. 验证 MCP: `/mcp` 确认两端 ✓ Connected

---

## 八、下一步计划

### 短期（本周）
1. ✅ CLAUDE.md v2 已完成（含动态优先 + 熔断 + 博弈识别启发）
2. 用更多题目测试 CLAUDE.md v2 的效果
3. 考虑 pwn.college VM 题（测试 hardware watchpoint + VM 逆向方法论）

### 中期
1. 积累 10+ 道题的失败模式，持续迭代 CLAUDE.md
2. 评估是否需要 Opus（如果 CLAUDE.md 优化后仍有智力瓶颈）
3. 开源 GitHub + 写 benchmark（N 道题，自动 X 道，半自动 Y 道）

### 长期
1. 如果 Claude Code 的 ReAct 控制不够 → 考虑 LangGraph 自建调度器
2. 扩展到 pwn 题（exploit 生成）
3. 写技术 blog / paper

---

## 九、关键文件索引

| 文件 | 位置 | 版本 | 用途 |
|------|------|------|------|
| CLAUDE.md | `C:\Users\Chen\Desktop\folder\` | v2 | Agent 逆向方法论 |
| dynamic_mcp_server.py | Kali `/home/kali/lab/ghidra-ai/` | v0.3 | 动态端 MCP Server |
| bridge_mcp_ghidra.py | `C:\Users\Chen\Desktop\ghidra-mcp\` | 原版 | 静态端 MCP Bridge |
| .claude.json | `C:\Users\Chen\` | - | Claude Code MCP 配置 |
| revagent_context_v04.md | 本文件 | v0.4 | 项目上下文同步文档 |
