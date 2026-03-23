"""
Project RevAgent - Dynamic Pwntools MCP Server v0.3
====================================================
v0.3 更新:
  - gdb_breakpoint_read: 支持 breakpoint_type (software/hardware/read_watch/write_watch/access_watch)
  - gdb_breakpoint_read: 支持 extra_commands（断点命中后执行自定义 GDB 命令，如 set $rax=0）
  - gdb_breakpoint_read: 支持 backtrace (bt) 输出

依赖:
    pip install mcp pwntools capstone
    # GDB: apt install gdb
"""

import asyncio
import json
import os
import re
import signal
import subprocess
import tempfile
from dataclasses import dataclass, asdict, field
from enum import Enum
from typing import Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

import pwn


# ═══════════════════════════════════════════════════════════════
# 1. 数据模型
# ═══════════════════════════════════════════════════════════════

class ExitReason(str, Enum):
    NORMAL = "normal_exit"
    CRASH = "crash_segfault"
    TIMEOUT = "timeout_killed"
    STOPPED = "stopped_by_signal"
    UNKNOWN = "unknown"


@dataclass
class DynamicTraceResult:
    exit_reason: str
    exit_code: Optional[int]
    signal_number: Optional[int]
    signal_name: Optional[str]
    stdout_head: str
    stderr_head: str
    registers: Optional[dict]
    core_dump_hint: str
    elapsed_seconds: float


@dataclass
class BreakpointResult:
    hit: bool
    registers: dict
    memory_dumps: list
    backtrace: str
    gdb_output: str
    error: Optional[str]


# ═══════════════════════════════════════════════════════════════
# 2. 执行引擎
# ═══════════════════════════════════════════════════════════════

MAX_EXECUTION_TIMEOUT = 30
MAX_OUTPUT_BYTES = 2048
MAX_GDB_OUTPUT = 4096


# ── Tool 1: run_dynamic_trace ────────────────────────────────

async def execute_binary(
    binary_path: str,
    args: list[str],
    stdin_data: Optional[str] = None,
    timeout: int = MAX_EXECUTION_TIMEOUT,
    env_vars: Optional[dict] = None,
) -> DynamicTraceResult:

    def _sync_run() -> DynamicTraceResult:
        import time
        start = time.monotonic()
        stdout_buf = b""
        exit_reason = ExitReason.UNKNOWN
        exit_code = None
        sig_num = None
        sig_name = None
        registers = None

        try:
            pwn.context.update(arch="amd64", os="linux", log_level="error")
            run_env = os.environ.copy()
            if env_vars:
                run_env.update(env_vars)

            io = pwn.process([binary_path] + args, timeout=timeout, env=run_env)

            if stdin_data:
                io.send(stdin_data.encode())

            try:
                stdout_buf = io.recvall(timeout=timeout)
            except EOFError:
                stdout_buf = io.buffer.get() if hasattr(io, 'buffer') else b""
            except pwn.PwnlibException:
                pass

            io.close()
            poll_val = io.poll(block=True)

            if poll_val == 0:
                exit_reason = ExitReason.NORMAL
                exit_code = 0
            elif poll_val is not None and poll_val < 0:
                sig_num = abs(poll_val)
                sig_name = signal.Signals(sig_num).name if sig_num in signal.valid_signals() else f"SIG_{sig_num}"
                exit_reason = ExitReason.CRASH if sig_num == signal.SIGSEGV else ExitReason.STOPPED
            elif poll_val is not None:
                exit_reason = ExitReason.NORMAL
                exit_code = poll_val
            else:
                exit_reason = ExitReason.TIMEOUT

            if exit_reason == ExitReason.CRASH:
                registers = _try_extract_registers_from_core(binary_path)

        except FileNotFoundError:
            raise ValueError(f"Binary not found: {binary_path}")
        except Exception as e:
            return DynamicTraceResult(
                exit_reason=ExitReason.UNKNOWN.value,
                exit_code=None, signal_number=None, signal_name=None,
                stdout_head=f"[ERROR] {type(e).__name__}: {str(e)[:500]}",
                stderr_head="", registers=None, core_dump_hint="",
                elapsed_seconds=time.monotonic() - start,
            )

        return DynamicTraceResult(
            exit_reason=exit_reason.value,
            exit_code=exit_code,
            signal_number=sig_num,
            signal_name=sig_name,
            stdout_head=stdout_buf[:MAX_OUTPUT_BYTES].decode("latin-1"),
            stderr_head="",
            registers=asdict(registers) if registers and hasattr(registers, '__dataclass_fields__') else registers,
            core_dump_hint=_find_core_file(binary_path),
            elapsed_seconds=round(time.monotonic() - start, 3),
        )

    return await asyncio.to_thread(_sync_run)


# ── Tool 2: gdb_breakpoint_read (v0.3: watchpoint + extra_commands + bt) ──

async def gdb_breakpoint_read(
    binary_path: str,
    args: list[str],
    breakpoint_addr: str,
    breakpoint_type: str = "software",
    memory_reads: list[dict] = None,
    extra_commands: list[str] = None,
    env_vars: Optional[dict] = None,
    timeout: int = MAX_EXECUTION_TIMEOUT,
) -> BreakpointResult:
    """
    GDB batch mode 断点 + 寄存器/内存/backtrace 读取。

    breakpoint_type:
      - "software"      → break *ADDR（默认，int3 软件断点）
      - "hardware"      → hbreak *ADDR（硬件断点，不修改指令，对自修改代码更安全）
      - "read_watch"    → rwatch *ADDR（硬件读 watchpoint：读取该地址时触发）
      - "write_watch"   → watch *ADDR（硬件写 watchpoint：写入该地址时触发）
      - "access_watch"  → awatch *ADDR（硬件读写 watchpoint：任何访问触发）

    extra_commands:
      断点命中后、读取寄存器/内存之前执行的自定义 GDB 命令。
      典型用途:
        - ["set $rax=0"]  — 绕过 ptrace 反调试（伪造返回值）
        - ["set {int}0x8413e0=0"] — 修改内存
        - ["continue", "continue"]  — 跳过前 N 次命中
    """

    def _sync_run() -> BreakpointResult:
        if memory_reads is None:
            mem_reads = []
        else:
            mem_reads = memory_reads

        cmds = []
        cmds.append("set pagination off")
        cmds.append("set confirm off")

        # 下断点（根据类型）
        bp_cmd_map = {
            "software":     f"break *{breakpoint_addr}",
            "hardware":     f"hbreak *{breakpoint_addr}",
            "read_watch":   f"rwatch *{breakpoint_addr}",
            "write_watch":  f"watch *{breakpoint_addr}",
            "access_watch": f"awatch *{breakpoint_addr}",
        }
        bp_cmd = bp_cmd_map.get(breakpoint_type, f"break *{breakpoint_addr}")
        cmds.append(bp_cmd)

        # run
        args_str = " ".join(f'"{a}"' if " " in a else a for a in args)
        cmds.append(f"run {args_str}")

        # 断点命中后：先执行 extra_commands
        if extra_commands:
            cmds.extend(extra_commands)

        # 读寄存器
        cmds.append("info registers")

        # backtrace
        cmds.append("bt 10")

        # 读内存
        for mr in mem_reads:
            addr = mr.get("address", "0")
            length = mr.get("length", 32)
            cmds.append(f"x/{length}bx {addr}")

        cmds.append("quit")

        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
            f.write("\n".join(cmds) + "\n")
            script_path = f.name

        try:
            run_env = os.environ.copy()
            if env_vars:
                run_env.update(env_vars)

            result = subprocess.run(
                ["gdb", "--batch", "-x", script_path, binary_path],
                capture_output=True, text=True, timeout=timeout, env=run_env,
            )

            output = result.stdout + "\n" + result.stderr
            output_truncated = output[:MAX_GDB_OUTPUT]

            registers = _parse_gdb_registers(output)
            mem_dumps = _parse_gdb_memory(output, mem_reads)
            backtrace = _parse_gdb_backtrace(output)
            hit = "Breakpoint" in output or "Hardware watchpoint" in output or "watchpoint" in output.lower()

            return BreakpointResult(
                hit=hit,
                registers=registers,
                memory_dumps=mem_dumps,
                backtrace=backtrace,
                gdb_output=output_truncated,
                error=None,
            )

        except subprocess.TimeoutExpired:
            return BreakpointResult(
                hit=False, registers={}, memory_dumps=[], backtrace="",
                gdb_output="", error=f"GDB timed out after {timeout}s",
            )
        except FileNotFoundError:
            return BreakpointResult(
                hit=False, registers={}, memory_dumps=[], backtrace="",
                gdb_output="", error="GDB not found. Install: apt install gdb",
            )
        except Exception as e:
            return BreakpointResult(
                hit=False, registers={}, memory_dumps=[], backtrace="",
                gdb_output="", error=f"{type(e).__name__}: {str(e)[:300]}",
            )
        finally:
            os.unlink(script_path)

    return await asyncio.to_thread(_sync_run)


def _parse_gdb_registers(output: str) -> dict:
    registers = {}
    pat = re.compile(
        r'^(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|rip|eflags)\s+'
        r'(0x[0-9a-fA-F]+)', re.MULTILINE
    )
    for m in pat.finditer(output):
        registers[m.group(1)] = m.group(2)
    return registers


def _parse_gdb_memory(output: str, memory_reads: list[dict]) -> list[dict]:
    dumps = []
    hex_pat = re.compile(r'(0x[0-9a-fA-F]+):\s+((?:0x[0-9a-fA-F]+\s*)+)')

    all_bytes = []
    for m in hex_pat.finditer(output):
        for bs in m.group(2).strip().split():
            all_bytes.append(int(bs, 16))

    offset = 0
    for mr in memory_reads:
        length = mr.get("length", 32)
        addr = mr.get("address", "0")
        chunk = all_bytes[offset:offset + length]
        offset += length
        dumps.append({
            "address": addr,
            "length": len(chunk),
            "hex": "".join(f"{b:02x}" for b in chunk),
            "ascii": "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk),
            "bytes": chunk,
        })

    return dumps


def _parse_gdb_backtrace(output: str) -> str:
    """提取 bt 输出"""
    lines = []
    capturing = False
    for line in output.split("\n"):
        if line.strip().startswith("#0 "):
            capturing = True
        if capturing:
            if line.strip().startswith("#") or line.strip().startswith("from "):
                lines.append(line.strip())
            elif lines:
                break
    return "\n".join(lines[:10])


# ── Tool 3: disassemble_bytes ────────────────────────────────

async def disassemble_raw_bytes(
    hex_bytes: str,
    arch: str = "x86_64",
    base_address: int = 0,
) -> dict:
    def _sync_run() -> dict:
        try:
            import capstone
        except ImportError:
            return {"error": "capstone not installed. Run: pip install capstone", "instructions": []}

        raw = bytes.fromhex(hex_bytes.replace(" ", "").replace("0x", ""))

        arch_map = {
            "x86_64": (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "amd64":  (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            "x86":    (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            "arm":    (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            "arm64":  (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }
        if arch not in arch_map:
            return {"error": f"Unsupported arch: {arch}", "instructions": []}

        md = capstone.Cs(*arch_map[arch])
        instructions = []
        for insn in md.disasm(raw, base_address):
            instructions.append({
                "address": f"0x{insn.address:x}",
                "bytes": insn.bytes.hex(),
                "mnemonic": insn.mnemonic,
                "op_str": insn.op_str,
                "text": f"{insn.mnemonic} {insn.op_str}".strip(),
            })

        return {
            "arch": arch,
            "base_address": f"0x{base_address:x}",
            "instruction_count": len(instructions),
            "instructions": instructions,
        }

    return await asyncio.to_thread(_sync_run)


# ── 辅助函数 ─────────────────────────────────────────────────

def _try_extract_registers_from_core(binary_path: str):
    core_path = _find_core_file(binary_path)
    if not core_path or not os.path.exists(core_path):
        return None
    try:
        core = pwn.Coredump(core_path)
        return {
            "rip": hex(core.rip), "rsp": hex(core.rsp), "rbp": hex(core.rbp),
            "rax": hex(core.rax), "rbx": hex(core.rbx), "rcx": hex(core.rcx),
            "rdx": hex(core.rdx), "rdi": hex(core.rdi), "rsi": hex(core.rsi),
        }
    except Exception:
        return None


def _find_core_file(binary_path: str) -> str:
    for c in ["./core", f"./core.{os.getpid()}", f"/tmp/core.{os.path.basename(binary_path)}"]:
        if os.path.exists(c):
            return c
    return ""


# ═══════════════════════════════════════════════════════════════
# 3. MCP Server
# ═══════════════════════════════════════════════════════════════

app = Server("revagent-dynamic")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="run_dynamic_trace",
            description=(
                "运行 ELF 二进制并捕获行为。返回结构化 JSON：退出原因、stdout、崩溃时寄存器。"
                "支持 env_vars 注入环境变量（如 OPENSSL_CONF=/dev/null）。"
                "【安全】内置 30 秒硬超时。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "ELF 文件绝对路径"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "命令行参数", "default": []},
                    "stdin_data": {"type": "string", "description": "stdin 输入数据", "default": None},
                    "timeout": {"type": "integer", "description": "最大秒数（上限30）", "default": 10},
                    "env_vars": {"type": "object", "description": "环境变量，如 {\"OPENSSL_CONF\":\"/dev/null\"}", "default": {}},
                },
                "required": ["binary_path"],
            },
        ),

        Tool(
            name="gdb_breakpoint_read",
            description=(
                "GDB batch mode：在指定地址下断点/watchpoint，命中后读寄存器、内存、backtrace。"
                "支持 5 种断点类型：software, hardware, read_watch, write_watch, access_watch。"
                "支持 extra_commands：断点命中后执行自定义 GDB 命令（如 set $rax=0 绕过反调试）。"
                "自动输出 backtrace (bt 10)。"
                "核心用途：获取运行时状态（加密密钥、VM 内存、反调试后的全局变量）。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "ELF 文件绝对路径"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "命令行参数", "default": []},
                    "breakpoint_addr": {"type": "string", "description": "地址（如 '0x403300'）或表达式（如 '*main+897'）"},
                    "breakpoint_type": {
                        "type": "string",
                        "description": "断点类型",
                        "enum": ["software", "hardware", "read_watch", "write_watch", "access_watch"],
                        "default": "software",
                    },
                    "memory_reads": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "address": {"type": "string"},
                                "length": {"type": "integer", "default": 32},
                            },
                            "required": ["address"],
                        },
                        "description": "命中后读取的内存区域列表",
                        "default": [],
                    },
                    "extra_commands": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "断点命中后执行的自定义 GDB 命令（如 ['set $rax=0', 'continue']）",
                        "default": [],
                    },
                    "env_vars": {"type": "object", "description": "环境变量", "default": {}},
                    "timeout": {"type": "integer", "description": "GDB 最大秒数（上限30）", "default": 15},
                },
                "required": ["binary_path", "breakpoint_addr"],
            },
        ),

        Tool(
            name="disassemble_bytes",
            description=(
                "反汇编原始字节为汇编指令（capstone）。用于 shellcode / 运行时代码分析。"
                "支持 x86_64, x86, arm, arm64。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hex_bytes": {"type": "string", "description": "十六进制字节串"},
                    "arch": {"type": "string", "enum": ["x86_64", "x86", "arm", "arm64"], "default": "x86_64"},
                    "base_address": {"type": "integer", "description": "基地址", "default": 0},
                },
                "required": ["hex_bytes"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:

    if name == "run_dynamic_trace":
        bp = arguments.get("binary_path", "")
        if not bp or not os.path.isfile(bp):
            return [TextContent(type="text", text=json.dumps({"error": f"File not found: {bp}"}))]
        try:
            r = await execute_binary(bp, arguments.get("args", []), arguments.get("stdin_data"),
                                     min(arguments.get("timeout", 10), MAX_EXECUTION_TIMEOUT), arguments.get("env_vars"))
            return [TextContent(type="text", text=json.dumps(asdict(r), indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)[:500]}))]

    elif name == "gdb_breakpoint_read":
        bp = arguments.get("binary_path", "")
        if not bp or not os.path.isfile(bp):
            return [TextContent(type="text", text=json.dumps({"error": f"File not found: {bp}"}))]
        addr = arguments.get("breakpoint_addr", "")
        if not addr:
            return [TextContent(type="text", text=json.dumps({"error": "breakpoint_addr required"}))]
        try:
            r = await gdb_breakpoint_read(
                bp, arguments.get("args", []), addr,
                arguments.get("breakpoint_type", "software"),
                arguments.get("memory_reads", []),
                arguments.get("extra_commands", []),
                arguments.get("env_vars"), min(arguments.get("timeout", 15), MAX_EXECUTION_TIMEOUT),
            )
            return [TextContent(type="text", text=json.dumps(asdict(r), indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)[:500]}))]

    elif name == "disassemble_bytes":
        hb = arguments.get("hex_bytes", "")
        if not hb:
            return [TextContent(type="text", text=json.dumps({"error": "hex_bytes required"}))]
        try:
            r = await disassemble_raw_bytes(hb, arguments.get("arch", "x86_64"), arguments.get("base_address", 0))
            return [TextContent(type="text", text=json.dumps(r, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)[:500]}))]

    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


# ═══════════════════════════════════════════════════════════════
# 4. 入口
# ═══════════════════════════════════════════════════════════════

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
