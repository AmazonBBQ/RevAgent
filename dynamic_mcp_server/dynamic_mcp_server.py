"""
Project RevAgent - Dynamic Pwntools MCP Server (架构草案 v0.1)
=============================================================
职责: 作为 MCP Server，封装 pwntools 能力，为 Agent Router 提供
      结构化的动态分析结果（寄存器状态、崩溃信息、程序输出等）。

运行方式: 
    python dynamic_mcp_server.py
    # 默认以 stdio 模式启动，供 MCP Inspector 或 Agent 直连
    # 生产环境可改为 SSE 模式监听端口

依赖:
    pip install mcp pwntools
"""

import asyncio
import json
import os
import signal
import tempfile
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional

# ── MCP SDK ──────────────────────────────────────────────────
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── Pwntools (延迟导入，避免污染全局) ────────────────────────
# pwntools 的 from pwn import * 会注入大量全局变量，
# 我们只按需导入必要模块
import pwn


# ═══════════════════════════════════════════════════════════════
# 1. 数据模型 - 结构化返回给大模型的 JSON Schema
# ═══════════════════════════════════════════════════════════════

class ExitReason(str, Enum):
    NORMAL = "normal_exit"
    CRASH = "crash_segfault"
    TIMEOUT = "timeout_killed"
    STOPPED = "stopped_by_signal"
    UNKNOWN = "unknown"


@dataclass
class RegisterSnapshot:
    """崩溃时的寄存器快照（x86_64）"""
    rip: str = "N/A"
    rsp: str = "N/A"
    rbp: str = "N/A"
    rax: str = "N/A"
    rbx: str = "N/A"
    rcx: str = "N/A"
    rdx: str = "N/A"
    rdi: str = "N/A"
    rsi: str = "N/A"
    r8:  str = "N/A"
    r9:  str = "N/A"


@dataclass
class DynamicTraceResult:
    """run_dynamic_trace 的标准化返回结构"""
    exit_reason: str
    exit_code: Optional[int]
    signal_number: Optional[int]
    signal_name: Optional[str]
    stdout_head: str          # 截取前 2048 字节，防止输出爆炸
    stderr_head: str
    registers: Optional[dict] # 崩溃时才有值
    core_dump_hint: str       # 提示 core 文件路径
    elapsed_seconds: float


# ═══════════════════════════════════════════════════════════════
# 2. 核心执行引擎 - 用 pwntools 运行目标并捕获状态
# ═══════════════════════════════════════════════════════════════

# 全局硬编码超时（秒），对应架构文档中的"熔断机制"
MAX_EXECUTION_TIMEOUT = 30
MAX_OUTPUT_BYTES = 2048


async def execute_binary(
    binary_path: str,
    args: list[str],
    stdin_data: Optional[str] = None,
    timeout: int = MAX_EXECUTION_TIMEOUT,
) -> DynamicTraceResult:
    """
    在子进程中运行目标二进制，捕获其退出状态。

    关键设计决策:
    - 使用 pwn.process() 而非 subprocess，获得 pwntools 的信号处理能力
    - 整个执行包裹在 asyncio.to_thread() 中，避免阻塞 MCP 事件循环
    - 硬编码 timeout，绝不允许进程无限挂起
    """

    def _sync_run() -> DynamicTraceResult:
        import time
        start = time.monotonic()

        stdout_buf = b""
        stderr_buf = b""
        exit_reason = ExitReason.UNKNOWN
        exit_code = None
        sig_num = None
        sig_name = None
        registers = None

        # ── 启动进程 ──
        try:
            # 设置 pwntools 上下文（关闭多余输出）
            pwn.context.update(
                arch="amd64",
                os="linux",
                log_level="error",  # 抑制 pwntools 的 banner 噪音
            )

            io = pwn.process(
                [binary_path] + args,
                timeout=timeout,
            )

            # ── 发送输入（如果有）──
            if stdin_data:
                io.send(stdin_data.encode())

            # ── 等待进程结束（带超时）──
            try:
                stdout_buf = io.recvall(timeout=timeout)
            except EOFError:
                stdout_buf = io.buffer.get() if hasattr(io, 'buffer') else b""
            except pwn.PwnlibException:
                # 超时或连接断开
                pass

            # ── 判断退出原因 ──
            io.close()
            poll_val = io.poll(block=True)

            if poll_val == 0:
                exit_reason = ExitReason.NORMAL
                exit_code = 0
            elif poll_val is not None and poll_val < 0:
                # 负值 = 被信号杀死
                sig_num = abs(poll_val)
                sig_name = signal.Signals(sig_num).name if sig_num in signal.valid_signals() else f"SIG_{sig_num}"
                if sig_num == signal.SIGSEGV:
                    exit_reason = ExitReason.CRASH
                else:
                    exit_reason = ExitReason.STOPPED
            elif poll_val is not None:
                exit_reason = ExitReason.NORMAL
                exit_code = poll_val
            else:
                exit_reason = ExitReason.TIMEOUT

            # ── 崩溃时尝试提取寄存器（通过 coredump）──
            if exit_reason == ExitReason.CRASH:
                registers = _try_extract_registers_from_core(binary_path)

        except FileNotFoundError:
            raise ValueError(f"Binary not found: {binary_path}")
        except Exception as e:
            # 兜底：确保绝不会因异常导致 Agent 挂死
            return DynamicTraceResult(
                exit_reason=ExitReason.UNKNOWN.value,
                exit_code=None,
                signal_number=None,
                signal_name=None,
                stdout_head=f"[EXECUTION ERROR] {type(e).__name__}: {str(e)[:500]}",
                stderr_head="",
                registers=None,
                core_dump_hint="",
                elapsed_seconds=time.monotonic() - start,
            )

        elapsed = time.monotonic() - start

        return DynamicTraceResult(
            exit_reason=exit_reason.value,
            exit_code=exit_code,
            signal_number=sig_num,
            signal_name=sig_name,
            stdout_head=stdout_buf[:MAX_OUTPUT_BYTES].decode("latin-1"),
            stderr_head=stderr_buf[:MAX_OUTPUT_BYTES].decode("latin-1") if stderr_buf else "",
            registers=asdict(registers) if registers else None,
            core_dump_hint=_find_core_file(binary_path),
            elapsed_seconds=round(elapsed, 3),
        )

    # 关键：在线程池中运行同步的 pwntools 代码，不阻塞 asyncio 循环
    return await asyncio.to_thread(_sync_run)


def _try_extract_registers_from_core(binary_path: str) -> Optional[RegisterSnapshot]:
    """
    尝试从 coredump 中提取寄存器。
    
    实现策略: 用 pwntools 的 Coredump 类解析 core 文件。
    如果没有 core 文件（ulimit 未设置），优雅降级返回 None。

    TODO(Phase 2): 
    - 集成 GDB batch mode 作为 fallback
    - 支持 ARM/MIPS 架构的寄存器映射
    """
    core_path = _find_core_file(binary_path)
    if not core_path or not os.path.exists(core_path):
        return None

    try:
        core = pwn.Coredump(core_path)
        snap = RegisterSnapshot(
            rip=hex(core.rip) if hasattr(core, 'rip') else "N/A",
            rsp=hex(core.rsp) if hasattr(core, 'rsp') else "N/A",
            rbp=hex(core.rbp) if hasattr(core, 'rbp') else "N/A",
            rax=hex(core.rax) if hasattr(core, 'rax') else "N/A",
            rbx=hex(core.rbx) if hasattr(core, 'rbx') else "N/A",
            rcx=hex(core.rcx) if hasattr(core, 'rcx') else "N/A",
            rdx=hex(core.rdx) if hasattr(core, 'rdx') else "N/A",
            rdi=hex(core.rdi) if hasattr(core, 'rdi') else "N/A",
            rsi=hex(core.rsi) if hasattr(core, 'rsi') else "N/A",
            r8=hex(core.r8)   if hasattr(core, 'r8')  else "N/A",
            r9=hex(core.r9)   if hasattr(core, 'r9')  else "N/A",
        )
        return snap
    except Exception:
        return None


def _find_core_file(binary_path: str) -> str:
    """查找可能的 core dump 文件路径"""
    candidates = [
        "./core",
        f"./core.{os.getpid()}",
        f"/tmp/core.{os.path.basename(binary_path)}",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    return ""


# ═══════════════════════════════════════════════════════════════
# 3. MCP Server 定义 - 注册 Tools 供 Agent 调用
# ═══════════════════════════════════════════════════════════════

app = Server("revagent-dynamic")


@app.list_tools()
async def list_tools() -> list[Tool]:
    """声明本 Server 暴露的所有 Tool"""
    return [
        Tool(
            name="run_dynamic_trace",
            description=(
                "运行一个 ELF 二进制文件并捕获其行为。"
                "返回结构化 JSON，包含退出原因（正常/崩溃/超时）、"
                "stdout 输出（截断至 2KB）、以及崩溃时的寄存器快照。"
                "适用场景：验证逆向猜想、触发特定路径、检测反调试。"
                "【安全】内置 30 秒硬超时，不会挂死。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {
                        "type": "string",
                        "description": "目标 ELF 文件的绝对路径",
                    },
                    "args": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "传递给目标的命令行参数",
                        "default": [],
                    },
                    "stdin_data": {
                        "type": "string",
                        "description": "要通过 stdin 发送给目标的数据（如 Flag 猜测值）",
                        "default": None,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "最大执行秒数（上限 30，防止挂死）",
                        "default": 10,
                    },
                },
                "required": ["binary_path"],
            },
        ),

        # ── 预留 Tool 位（Phase 2 扩展）──
        # Tool(name="attach_gdb_breakpoint", ...),
        #   → 在指定地址下断点，返回命中时的上下文
        # Tool(name="patch_binary_bytes", ...),
        #   → 原地 Patch 二进制（如 NOP 掉反调试 syscall）
        # Tool(name="run_angr_explore", ...),
        #   → 接收 Ghidra 端生成的 Angr 脚本框架并执行
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    """Tool 调用路由"""

    if name == "run_dynamic_trace":
        # ── 参数校验 ──
        binary_path = arguments.get("binary_path", "")
        if not binary_path or not os.path.isfile(binary_path):
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": f"File not found or not accessible: {binary_path}",
                    "hint": "请确认路径正确且文件有执行权限 (chmod +x)",
                }),
            )]

        args = arguments.get("args", [])
        stdin_data = arguments.get("stdin_data")
        timeout = min(arguments.get("timeout", 10), MAX_EXECUTION_TIMEOUT)

        # ── 执行 ──
        try:
            result = await execute_binary(
                binary_path=binary_path,
                args=args,
                stdin_data=stdin_data,
                timeout=timeout,
            )
            return [TextContent(
                type="text",
                text=json.dumps(asdict(result), indent=2, ensure_ascii=False),
            )]
        except ValueError as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        except Exception as e:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": f"Unexpected: {type(e).__name__}: {str(e)[:300]}",
                }),
            )]

    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


# ═══════════════════════════════════════════════════════════════
# 4. 入口 - 启动 MCP Server
# ═══════════════════════════════════════════════════════════════

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options(),
        )


if __name__ == "__main__":
    asyncio.run(main())
