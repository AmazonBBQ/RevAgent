# RevAgent — Milestone 规划

**最后更新：2026-03-22**

---

## M1: 基础设施稳定性（优先级：🔴 最高）

**目标**：让现有工具链在实战中不掉链子。当前最大的非智力瓶颈是工具本身的可靠性。

**预计工作量**：2-3 个会话

| 任务 | 状态 | 说明 |
|------|------|------|
| pwntools-dynamic 断连检测 | ❌ | bedtime 第 3-4 轮之间断连，Agent 浪费整轮用 Ghidra Java 脚本绕道 |
| gdb_breakpoint_read 加 stdin_data | ❌ | 当前只能通过 bash 包装传入输入，PIE binary 调试极不方便 |
| gdb_breakpoint_read 加 continue_count | ❌ | 支持"断点命中 N 次，每次 dump 数据"，为 384 轮游戏场景设计 |
| 自动计算 PIE base address | ❌ | 当前手动算偏移（Ghidra addr + slide），应该封装到 tool 里 |
| run_dynamic_trace 的 stdout 截断问题 | ❌ | Rust binary 的 write 输出有时丢失，需要更健壮的捕获 |

**验收标准**：用 tomb 重新跑一次，全程无工具故障；用 bedtime 跑一次 GDB 脚本 dump，stdin_data 正常传入。

---

## M2: Agent 策略迭代（优先级：🟡 高）

**目标**：让 CLAUDE.md 的规则更精准，减少人工干预次数。

**预计工作量**：3-5 个会话（边测题边迭代）

| 任务 | 状态 | 说明 |
|------|------|------|
| CLAUDE.md v3 | ❌ | 纳入 bedtime 全部教训：巨型 main 不反编译、Rust 标准库不追踪、输入失败 3 次切 GDB |
| 程序类型自动分类流程 | ❌ | 先运行 → 根据交互模式分类 → 自动选择分析策略模板 |
| "输入格式探测"标准流程 | ❌ | 所有输入失败时：1) strace 看 syscall 2) GDB 断点在解析函数 3) 逐步单步 |
| 博弈题启发规则 | ❌ | 多计数器 + %运算 + XOR 聚合 → 提示 Nim/Sprague-Grundy |
| "dump 运行时数据"触发条件 | ❌ | 规则 8 在 bedtime 第 4 轮才被人类触发，应更早自动触发 |

**验收标准**：在一道新 Hard 题上，人工干预 ≤ 2 次（当前 tomb 需要 4 次）。

---

## M3: 工具能力扩展（优先级：🟡 高）

**目标**：补齐 tomb 和 bedtime 暴露的工具缺失。

**预计工作量**：3-4 个会话

| 任务 | 状态 | 说明 |
|------|------|------|
| patch_binary Tool | ❌ | NOP 反调试代码（tomb 的 proc/puts 可直接 patch） |
| run_gdb_script Tool | ❌ | 执行完整的 GDB Python 脚本（而非单个断点），支持复杂多断点场景 |
| auto_pie_break Tool | ❌ | 封装 starti → 读 base → 计算运行时地址 → 下断点，一步完成 |
| run_interactive Tool | ❌ | 多轮 pwntools 交互脚本（384 轮游戏场景），超时保护 |
| VM 逆向测试 | ❌ | 用 pwn.college 或 DiceCTF VM 题测试 hardware watchpoint 方法论 |

**验收标准**：patch_binary 能 NOP tomb 的反调试并直接运行拿 flag；auto_pie_break 一个 tool call 完成 PIE 断点。

---

## M4: 模型与策略评估（优先级：🟢 中）

**目标**：量化评估不同模型/策略组合的效果。

**预计工作量**：2-3 个会话

| 任务 | 状态 | 说明 |
|------|------|------|
| Opus 4.6 对比测试 | ❌ | 在 bedtime 或同级别题上测 Opus，评估智力差距的实际影响 |
| Gemini CLI 对比测试 | ❌ | 同一 MCP Server 接 Gemini，评估模型无关性 |
| 纯 Claude Code baseline | ❌ | 无 Ghidra MCP，纯终端 Agent 能做到什么程度 |
| 纯 Ghidra MCP baseline | ❌ | 无动态端，纯静态分析能做到什么程度 |

**验收标准**：产出对比表，每个组合在 5 道题上的成功率/人工干预次数/耗时。

---

## M5: Benchmark 与开源（优先级：🟢 中）

**目标**：把项目从"个人实验"升级为"可复现的研究成果"。

**预计工作量**：5-8 个会话

| 任务 | 状态 | 说明 |
|------|------|------|
| 题库建设 | ❌ | 选 15-20 道公开 Rev 题，按类型分层（crackme / 加密 / 反调试 / 博弈 / VM） |
| 自动化测试框架 | ❌ | 脚本化：导入 Ghidra → 启动 MCP → 运行 Claude Code → 记录结果 |
| 评测指标定义 | ❌ | 全自动 / 半自动（N 次干预）/ 失败；tool call 次数；耗时；token 消耗 |
| Benchmark 运行 | ❌ | 在全部题目上跑 RevAgent 完整版 + baseline 对比 |
| GitHub 开源 | ❌ | README + 安装指南 + 示例 + benchmark 数据 |
| 技术 blog / paper | ❌ | 写一篇完整的技术文章，含架构、方法论、评测结果 |

**验收标准**：GitHub repo 有完整 README，任何人按照指南能在 30 分钟内复现环境；benchmark 数据表在 README 中可见。

---

## M6: 高级功能（优先级：⚪ 低，长期）

| 任务 | 说明 |
|------|------|
| LangGraph Agent Router | 自建调度器，精确控制 ReAct 循环、token 预算、多路并行 |
| Angr 集成 | 对约束可解的题目自动生成 Angr 脚本 |
| 扩展到 pwn 题 | exploit 生成（stack overflow, heap, format string） |
| 多 Agent 协作 | 一个 Agent 做静态，一个做动态，Router 协调 |
| Web UI | 可视化分析过程，非 CTF 玩家也能理解 |

---

## 执行原则

1. **每次会话聚焦一个 milestone 的 1-2 个任务**，不要跨 milestone
2. **每个 milestone 内的任务按顺序做**，前面的是后面的前置条件
3. **M1 → M2 → M3 可以交叉**（做 M2 题目压测时发现 M1/M3 的新需求）
4. **M4 和 M5 在 M1-M3 基本完成后再开始**
5. **M6 是"nice to have"**，不要在 M1-M5 完成前碰
6. **每完成一个任务就更新 CHANGELOG.md**
