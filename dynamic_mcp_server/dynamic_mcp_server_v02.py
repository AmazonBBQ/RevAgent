"""
Project RevAgent - Dynamic Pwntools MCP Server v0.2
====================================================
更新内容:
  - run_dynamic_trace: 新增 env_vars 参数（解决 OPENSSL_CONF 等环境依赖）
  - gdb_breakpoint_read: GDB batch mode 断点 + 寄存器/内存读取（核心新功能）
  - disassemble_bytes: 反汇编原始字节（用于分析 shellcode）

运行方式: 
    python3 dynamic_mcp_server.py

依赖:
    pip install mcp pwntools capstone
    # GDB 需要系统安装: apt install gdb
"""

import asyncio
import json
import os
import re
import signal
import subprocess
import tempfile
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional

# ── MCP SDK ──────────────────────────────────────────────────
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# ── Pwntools ─────────────────────────────────────────────────
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
    stdout_head: str
    stderr_head: str
    registers: Optional[dict]
    core_dump_hint: str
    elapsed_seconds: float


@dataclass
class BreakpointResult:
    """gdb_breakpoint_read 的返回结构"""
    hit: bool
    registers: dict
    memory_dumps: list  # [{address, hex, ascii}]
    gdb_output: str     # 完整 GDB 输出（截断）
    error: Optional[str]


# ═══════════════════════════════════════════════════════════════
# 2. 执行引擎
# ═══════════════════════════════════════════════════════════════

MAX_EXECUTION_TIMEOUT = 30
MAX_OUTPUT_BYTES = 2048
MAX_GDB_OUTPUT = 4096


# ── Tool 1: run_dynamic_trace（已增强：支持 env_vars）────────

async def execute_binary(
    binary_path: str,
    args: list[str],
    stdin_data: Optional[str] = None,
    timeout: int = MAX_EXECUTION_TIMEOUT,
    env_vars: Optional[dict] = None,
) -> DynamicTraceResult:
    """
    运行目标二进制，捕获退出状态。
    
    v0.2 新增: env_vars 参数，支持注入环境变量。
    典型用途: {"OPENSSL_CONF": "/dev/null"} 解决静态链接 OpenSSL 崩溃。
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

        try:
            pwn.context.update(
                arch="amd64",
                os="linux",
                log_level="error",
            )

            # ── 构建环境变量 ──
            run_env = os.environ.copy()
            if env_vars:
                run_env.update(env_vars)

            io = pwn.process(
                [binary_path] + args,
                timeout=timeout,
                env=run_env,
            )

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
                if sig_num == signal.SIGSEGV:
                    exit_reason = ExitReason.CRASH
                else:
                    exit_reason = ExitReason.STOPPED
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
                stdout_head=f"[EXECUTION ERROR] {type(e).__name__}: {str(e)[:500]}",
                stderr_head="", registers=None, core_dump_hint="",
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

    return await asyncio.to_thread(_sync_run)


# ── Tool 2: gdb_breakpoint_read（GDB batch mode）────────────

async def gdb_breakpoint_read(
    binary_path: str,
    args: list[str],
    breakpoint_addr: str,
    memory_reads: list[dict],
    env_vars: Optional[dict] = None,
    timeout: int = MAX_EXECUTION_TIMEOUT,
) -> BreakpointResult:
    """
    用 GDB batch mode 在指定地址下断点，命中后读取寄存器和内存。
    
    这是 RevAgent 的核心差异化 Tool —— 解决 tomb 类题目中
    "需要运行时状态但无法纯静态计算"的问题。
    
    技术选型: GDB batch mode（非 pwntools gdb.attach）
    原因: batch mode 同步执行，不会挂起，输出可解析。
    """

    def _sync_run() -> BreakpointResult:
        # ── 构建 GDB 命令脚本 ──
        gdb_commands = []
        gdb_commands.append("set pagination off")
        gdb_commands.append("set confirm off")
        
        # 下断点
        gdb_commands.append(f"break *{breakpoint_addr}")
        
        # 构建 run 命令（带参数）
        args_str = " ".join(f'"{a}"' if " " in a else a for a in args)
        gdb_commands.append(f"run {args_str}")
        
        # 断点命中后：打印寄存器
        gdb_commands.append("info registers")
        
        # 读取指定内存区域
        for mr in memory_reads:
            addr = mr.get("address", "0")
            length = mr.get("length", 32)
            # x/Nbx addr → 打印 N 字节的 hex
            gdb_commands.append(f"x/{length}bx {addr}")
        
        gdb_commands.append("quit")
        
        # ── 写入临时脚本文件 ──
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".gdb", delete=False
        ) as f:
            f.write("\n".join(gdb_commands) + "\n")
            script_path = f.name
        
        try:
            # ── 构建环境 ──
            run_env = os.environ.copy()
            if env_vars:
                run_env.update(env_vars)
            
            # ── 执行 GDB batch ──
            result = subprocess.run(
                ["gdb", "--batch", "-x", script_path, binary_path],
                capture_output=True,
                text=True,
                timeout=timeout,
                env=run_env,
            )
            
            output = result.stdout + "\n" + result.stderr
            output_truncated = output[:MAX_GDB_OUTPUT]
            
            # ── 解析寄存器 ──
            registers = _parse_gdb_registers(output)
            
            # ── 解析内存 dump ──
            mem_dumps = _parse_gdb_memory(output, memory_reads)
            
            # ── 判断是否命中断点 ──
            hit = "Breakpoint 1" in output and "info registers" in "\n".join(gdb_commands)
            
            return BreakpointResult(
                hit=hit,
                registers=registers,
                memory_dumps=mem_dumps,
                gdb_output=output_truncated,
                error=None,
            )
            
        except subprocess.TimeoutExpired:
            return BreakpointResult(
                hit=False, registers={}, memory_dumps=[],
                gdb_output="", error=f"GDB timed out after {timeout}s",
            )
        except FileNotFoundError:
            return BreakpointResult(
                hit=False, registers={}, memory_dumps=[],
                gdb_output="", error="GDB not found. Install with: apt install gdb",
            )
        except Exception as e:
            return BreakpointResult(
                hit=False, registers={}, memory_dumps=[],
                gdb_output="", error=f"{type(e).__name__}: {str(e)[:300]}",
            )
        finally:
            os.unlink(script_path)

    return await asyncio.to_thread(_sync_run)


def _parse_gdb_registers(output: str) -> dict:
    """从 GDB 'info registers' 输出中提取寄存器值"""
    registers = {}
    reg_pattern = re.compile(
        r'^(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|rip|eflags)\s+'
        r'(0x[0-9a-fA-F]+)',
        re.MULTILINE
    )
    for match in reg_pattern.finditer(output):
        registers[match.group(1)] = match.group(2)
    return registers


def _parse_gdb_memory(output: str, memory_reads: list[dict]) -> list[dict]:
    """从 GDB 'x/Nbx' 输出中提取内存内容"""
    dumps = []
    
    # GDB x/bx 输出格式: 0x8413e0: 0xf9 0x00 0x16 ...
    hex_line_pattern = re.compile(r'(0x[0-9a-fA-F]+):\s+((?:0x[0-9a-fA-F]+\s*)+)')
    
    all_bytes = []
    current_base = None
    
    for match in hex_line_pattern.finditer(output):
        addr = int(match.group(1), 16)
        if current_base is None:
            current_base = addr
        byte_strs = match.group(2).strip().split()
        for bs in byte_strs:
            all_bytes.append(int(bs, 16))
    
    # 将收集到的字节分配给各个 memory_read 请求
    offset = 0
    for mr in memory_reads:
        length = mr.get("length", 32)
        addr = mr.get("address", "0")
        chunk = all_bytes[offset:offset + length]
        offset += length
        
        hex_str = "".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        
        dumps.append({
            "address": addr,
            "length": len(chunk),
            "hex": hex_str,
            "ascii": ascii_str,
            "bytes": chunk,
        })
    
    return dumps


# ── Tool 3: disassemble_bytes ────────────────────────────────

async def disassemble_raw_bytes(
    hex_bytes: str,
    arch: str = "x86_64",
    base_address: int = 0,
) -> dict:
    """
    用 capstone 反汇编原始字节。
    用于分析自解密 shellcode、运行时生成的代码。
    """
    def _sync_run() -> dict:
        try:
            import capstone
        except ImportError:
            return {
                "error": "capstone not installed. Run: pip install capstone",
                "instructions": [],
            }
        
        raw = bytes.fromhex(hex_bytes.replace(" ", "").replace("0x", ""))
        
        # 选择架构
        if arch in ("x86_64", "amd64", "x64"):
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch in ("x86", "i386", "x32"):
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif arch in ("arm", "arm32"):
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif arch in ("arm64", "aarch64"):
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            return {"error": f"Unsupported arch: {arch}", "instructions": []}
        
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

def _try_extract_registers_from_core(binary_path: str) -> Optional[RegisterSnapshot]:
    core_path = _find_core_file(binary_path)
    if not core_path or not os.path.exists(core_path):
        return None
    try:
        core = pwn.Coredump(core_path)
        return RegisterSnapshot(
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
    except Exception:
        return None


def _find_core_file(binary_path: str) -> str:
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
# 3. MCP Server 定义
# ═══════════════════════════════════════════════════════════════

app = Server("revagent-dynamic")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ── Tool 1: run_dynamic_trace（增强版）──
        Tool(
            name="run_dynamic_trace",
            description=(
                "运行 ELF 二进制并捕获行为。返回结构化 JSON：退出原因、stdout（截断 2KB）、崩溃时寄存器。"
                "支持 env_vars 注入环境变量（如 OPENSSL_CONF=/dev/null 解决静态链接崩溃）。"
                "【安全】内置 30 秒硬超时。"
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
                        "description": "命令行参数",
                        "default": [],
                    },
                    "stdin_data": {
                        "type": "string",
                        "description": "通过 stdin 发送的数据",
                        "default": None,
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "最大执行秒数（上限 30）",
                        "default": 10,
                    },
                    "env_vars": {
                        "type": "object",
                        "description": "注入的环境变量。如 {\"OPENSSL_CONF\": \"/dev/null\"} 或 {\"LD_PRELOAD\": \"/usr/lib/libssl.so\"}",
                        "default": {},
                    },
                },
                "required": ["binary_path"],
            },
        ),

        # ── Tool 2: gdb_breakpoint_read ──
        Tool(
            name="gdb_breakpoint_read",
            description=(
                "在指定地址下断点，运行二进制，断点命中后读取寄存器和内存区域。"
                "使用 GDB batch mode（同步、不会挂死）。"
                "核心用途：获取运行时被反调试/动态修改的全局变量（如加密密钥）。"
                "注意：断点本身可能触发反调试检测，可配合 patch_binary 使用。"
                "【安全】内置超时。"
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
                        "description": "命令行参数（如 flag 猜测值）",
                        "default": [],
                    },
                    "breakpoint_addr": {
                        "type": "string",
                        "description": "断点地址（如 '0x403300' 或 '*main+897'）",
                    },
                    "memory_reads": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "address": {"type": "string", "description": "内存地址（如 '0x8413e0'）"},
                                "length": {"type": "integer", "description": "读取字节数", "default": 32},
                            },
                            "required": ["address"],
                        },
                        "description": "断点命中后要读取的内存区域列表",
                        "default": [],
                    },
                    "env_vars": {
                        "type": "object",
                        "description": "注入的环境变量",
                        "default": {},
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "GDB 最大执行秒数（上限 30）",
                        "default": 15,
                    },
                },
                "required": ["binary_path", "breakpoint_addr"],
            },
        ),

        # ── Tool 3: disassemble_bytes ──
        Tool(
            name="disassemble_bytes",
            description=(
                "反汇编原始字节为汇编指令。用于分析自解密 shellcode、运行时生成的代码。"
                "支持 x86_64, x86, arm, arm64 架构。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "hex_bytes": {
                        "type": "string",
                        "description": "十六进制字节串（如 'b839050000c3' 或 '0xb8 0x39 0x05'）",
                    },
                    "arch": {
                        "type": "string",
                        "description": "目标架构",
                        "enum": ["x86_64", "x86", "arm", "arm64"],
                        "default": "x86_64",
                    },
                    "base_address": {
                        "type": "integer",
                        "description": "反汇编基地址",
                        "default": 0,
                    },
                },
                "required": ["hex_bytes"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:

    # ── run_dynamic_trace ──
    if name == "run_dynamic_trace":
        binary_path = arguments.get("binary_path", "")
        if not binary_path or not os.path.isfile(binary_path):
            return [TextContent(type="text", text=json.dumps({
                "error": f"File not found: {binary_path}",
                "hint": "确认路径正确且有执行权限 (chmod +x)",
            }))]

        args = arguments.get("args", [])
        stdin_data = arguments.get("stdin_data")
        timeout = min(arguments.get("timeout", 10), MAX_EXECUTION_TIMEOUT)
        env_vars = arguments.get("env_vars", None)

        try:
            result = await execute_binary(
                binary_path=binary_path,
                args=args,
                stdin_data=stdin_data,
                timeout=timeout,
                env_vars=env_vars,
            )
            return [TextContent(type="text", text=json.dumps(asdict(result), indent=2, ensure_ascii=False))]
        except ValueError as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)}))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({
                "error": f"Unexpected: {type(e).__name__}: {str(e)[:300]}",
            }))]

    # ── gdb_breakpoint_read ──
    elif name == "gdb_breakpoint_read":
        binary_path = arguments.get("binary_path", "")
        if not binary_path or not os.path.isfile(binary_path):
            return [TextContent(type="text", text=json.dumps({
                "error": f"File not found: {binary_path}",
            }))]

        args = arguments.get("args", [])
        bp_addr = arguments.get("breakpoint_addr", "")
        mem_reads = arguments.get("memory_reads", [])
        env_vars = arguments.get("env_vars", None)
        timeout = min(arguments.get("timeout", 15), MAX_EXECUTION_TIMEOUT)

        if not bp_addr:
            return [TextContent(type="text", text=json.dumps({
                "error": "breakpoint_addr is required",
            }))]

        try:
            result = await gdb_breakpoint_read(
                binary_path=binary_path,
                args=args,
                breakpoint_addr=bp_addr,
                memory_reads=mem_reads,
                env_vars=env_vars,
                timeout=timeout,
            )
            return [TextContent(type="text", text=json.dumps(asdict(result), indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({
                "error": f"Unexpected: {type(e).__name__}: {str(e)[:300]}",
            }))]

    # ── disassemble_bytes ──
    elif name == "disassemble_bytes":
        hex_bytes = arguments.get("hex_bytes", "")
        arch = arguments.get("arch", "x86_64")
        base_addr = arguments.get("base_address", 0)

        if not hex_bytes:
            return [TextContent(type="text", text=json.dumps({
                "error": "hex_bytes is required",
            }))]

        try:
            result = await disassemble_raw_bytes(hex_bytes, arch, base_addr)
            return [TextContent(type="text", text=json.dumps(result, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({
                "error": f"Unexpected: {type(e).__name__}: {str(e)[:300]}",
            }))]

    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


# ═══════════════════════════════════════════════════════════════
# 4. 入口
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
