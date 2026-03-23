# RevAgent — CHANGELOG

## 2026-03-21: Phase 1 基础设施搭建
- Kali 上部署 dynamic_mcp_server.py v0.1（run_dynamic_trace）
- Windows 上编译安装 GhidraMCP 插件（Maven + JDK 25）
- 启动 bridge_mcp_ghidra.py（163 tools）
- 安装 Claude Code v2.1.81，配置双端 MCP
- **simp-password** ✅ 全自动解出（4 次 tool call）
- **requiem** ✅ 全自动解出（~10 次 tool call，stripped Rust XOR）

## 2026-03-22: tomb + bedtime 压测
### tomb (Blackbeard's Tomb, 500pt) ✅
- 第一轮失败：漏掉 proc() 和自定义 puts() 两层反调试
- 开发 v0.2：加 env_vars 支持（解决 OpenSSL 崩溃）
- 开发 v0.3：加 gdb_breakpoint_read（5 种断点 + watchpoint + extra_commands + bt）+ disassemble_bytes
- 第二轮成功：gdb_breakpoint_read 暴露 tomb_key 每次不同 → 追查到 proc() → Python 重放 5 层 XOR → flag 解出
- **Flag**: `BCCTF{Buri3d_at_sea_Ent0m3d_amm0nG_th3_w4v3S}`
- **教训**: GDB 本身触发反调试；全局变量多处修改 → Python 重放最可靠

### bedtime (DiceCTF 2026) ❌ 分析阶段
- 4 轮尝试，每轮递进
- 创建 CLAUDE.md v1 → v2（9 条规则 + 熔断 + 程序类型识别 + 规则 8 dump 数据）
- Agent 发现：384 轮循环、PRNG 常量、9999 哨兵、B-tree、stride=4 解析器
- Agent 在第 4 轮完全采用"实验科学家"模式，写了 14 个 GDB Python 脚本
- "1 9999\n" × 384 通过计数检查（动态实验发现，非静态分析）
- 未攻破：正确输入格式、bounded Nim 语义识别
- **教训**: 巨型 main 不要反编译；从数据推断算法比从代码推断高效；pwntools 可能断连需检测

---

## Next: M1 基础设施稳定性
- [ ] pwntools-dynamic 断连检测（bedtime 第 3-4 轮之间断连浪费整轮）
- [ ] gdb_breakpoint_read 加 stdin_data 参数（当前只能通过 bash 包装）
- [ ] gdb_breakpoint_read 加 continue_count（断点命中 N 次每次 dump）
- [ ] 自动计算 PIE base address（当前手动算偏移）
- [ ] CLAUDE.md v3（加入 bedtime 最新教训）

## Backlog
- M2: Agent 策略迭代（程序类型自动分类、输入格式探测流程）
- M3: patch_binary Tool、run_interactive_script Tool、VM 题测试
- M4: Benchmark 建立（10-20 题）、GitHub 开源、技术 blog
