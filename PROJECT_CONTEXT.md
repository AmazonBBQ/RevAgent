# RevAgent — 项目上下文 (v0.5)
**最后更新：2026-03-22**

## 项目一句话
基于 MCP 协议的"动静结合" AI 逆向分析 Agent。Ghidra 静态分析（163 tools）+ GDB/pwntools 动态执行统一编排，辅助 CTF Reverse 解题。

## 架构
```
Claude Code (Sonnet 4.6, Pro) + CLAUDE.md v2
  ├── ghidra-mcp (stdio) → bridge_mcp_ghidra.py → Ghidra 12.0 HTTP :8089 [Windows]
  └── pwntools-dynamic (stdio over SSH) → dynamic_mcp_server.py v0.3 [Kali 192.168.239.129]
       Tools: run_dynamic_trace, gdb_breakpoint_read (5种断点+watchpoint+extra_commands+bt), disassemble_bytes
```

## 当前能力边界
| 能力 | 状态 | 验证题目 |
|------|------|---------|
| 明文比较 / 固定 XOR | ✅ 全自动 | simp-password, requiem |
| 多层 XOR + 反调试 + shellcode | ✅ 半自动 (4次人工) | tomb (500pt) |
| 博弈引擎 / 巨型 Rust binary | ❌ 分析阶段 | bedtime (DiceCTF) |
| VM / 字节码解释器 | 未测试 | — |

## 关键文件
| 文件 | 路径 |
|------|------|
| CLAUDE.md v2 | `C:\Users\Chen\Desktop\folder\\claude\CLAUDE.md` |
| .claude.json | `C:\Users\Chen\.claude.json` |
| dynamic_mcp_server.py v0.3 | Kali `/home/kali/lab/ghidra-ai/dynamic_mcp_server.py` |
| bridge_mcp_ghidra.py | `C:\Users\Chen\Desktop\ghidra-mcp\` |

## 已识别的核心问题
1. **Thinking 卡顿**：Agent 在 thinking 中做密集计算而非写脚本（CLAUDE.md 3 分钟规则部分解决）
2. **pwntools-dynamic 断连**：SSH 会话不稳定，需要检测和自动重连
3. **PIE binary GDB 断点**：需要先 starti 获取 base address，当前靠手动计算偏移
4. **输入格式靠猜**：bedtime 所有输入都返回 "bad"，应该用 GDB 断点分析解析函数
5. **博弈/算法语义识别**：超出 Sonnet 4.6 能力，需要 Opus 或人类指导

## 启动检查清单
1. `ssh kali@192.168.239.129 "echo ok"`
2. Ghidra → 打开二进制 → Tools → GhidraMCP → Restart Server
3. `curl -UseBasicParsing http://127.0.0.1:8089/check_connection`
4. `cd C:\Users\Chen\Desktop\folder\claude && claude --dangerously-skip-permissions`
5. `/mcp` 确认两端 ✓ Connected

## 当前 Milestone
→ 见 CHANGELOG.md 末尾的 "Next" 部分
