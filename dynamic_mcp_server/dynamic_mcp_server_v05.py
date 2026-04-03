"""
Project RevAgent - Dynamic Pwntools MCP Server v0.5
====================================================
v0.5 更新 (M2/M3: 工具能力扩展):
  1. [run_gdb_script] 新 tool：一步完成"写 GDB Python 脚本 → 执行 → 读结果文件"
     - 解决 locked_in 中 Agent 每次需要 3-5 次 tool call 的问题
     - 脚本结果写 /tmp/revagent/，自动读取并返回
  2. [patch_binary] 新 tool：NOP 指定地址范围的字节（绕过反调试）
     - 支持 NOP、自定义字节、自动备份
  3. [run_dynamic_trace] timeout 上限提升到 120 秒（GDB Python 脚本需要更长时间）
  4. [stdin_data] 修复转义处理：\\n \\t \\r \\0 自动转为真实字符
  5. [gdb_breakpoint_read] use_starti 参数提升到 v0.5 正式支持

v0.4 更新 (M1: 基础设施稳定性):
  1. [ping] 健康检查
  2. [gdb_breakpoint_read] stdin_data + continue_count
  3. [get_pie_base] PIE base address 自动获取
  4. [run_dynamic_trace] 修复 stdout 截断

依赖:
    pip install mcp pwntools capstone
    # GDB: apt install gdb
"""

import asyncio
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
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
class BreakpointHitData:
    """单次断点命中的数据"""
    hit_number: int
    registers: dict
    memory_dumps: list
    backtrace: str


@dataclass
class BreakpointResult:
    hit: bool
    hit_count: int
    registers: dict
    memory_dumps: list
    backtrace: str
    all_hits: list
    gdb_output: str
    error: Optional[str]


# ═══════════════════════════════════════════════════════════════
# 2. 常量与配置
# ═══════════════════════════════════════════════════════════════

MAX_EXECUTION_TIMEOUT = 120    # v0.5: 从 30 提升到 120（GDB Python 脚本需要更长）
MAX_OUTPUT_BYTES = 8192        # v0.5: 从 4096 提升到 8192
MAX_GDB_OUTPUT = 8192
MAX_CONTINUE_COUNT = 200
MAX_GDB_SCRIPT_OUTPUT = 32768  # v0.5: run_gdb_script 结果文件最大读取字节

WORK_DIR = "/tmp/revagent"
os.makedirs(WORK_DIR, exist_ok=True)


# ═══════════════════════════════════════════════════════════════
# 3. 辅助函数
# ═══════════════════════════════════════════════════════════════

def _unescape_stdin(s: str) -> str:
    """
    v0.5: 处理 MCP JSON 传递中的转义序列。
    Claude Code 发送 "\\n" 时，Python 收到的是字面量 backslash+n，需要转为真实换行。
    """
    return re.sub(
        r'\\([ntr0])',
        lambda m: {'n': '\n', 't': '\t', 'r': '\r', '0': '\0'}[m.group(1)],
        s
    )


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
    hex_pat = re.compile(r'(0x[0-9a-fA-F]+)(?:\s+<[^>]+>)?:\s+((?:0x[0-9a-fA-F]+\s*)+)')

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


def _parse_multi_hits(output: str, memory_reads: list[dict]) -> list:
    """解析 continue_count 模式的多次命中数据"""
    hits = []
    sections = re.split(r'=== BREAKPOINT HIT #(\d+) ===', output)
    for i in range(1, len(sections) - 1, 2):
        hit_num = int(sections[i])
        hit_output = sections[i + 1]
        registers = _parse_gdb_registers(hit_output)
        mem_dumps = _parse_gdb_memory(hit_output, memory_reads)
        backtrace = _parse_gdb_backtrace(hit_output)
        hits.append({
            "hit_number": hit_num,
            "registers": registers,
            "memory_dumps": mem_dumps,
            "backtrace": backtrace,
        })
    return hits


# ═══════════════════════════════════════════════════════════════
# 4. 执行引擎
# ═══════════════════════════════════════════════════════════════

# ── Tool 1: run_dynamic_trace ────────────────────────────────

async def execute_binary(
    binary_path: str,
    args: list[str],
    stdin_data: Optional[str] = None,
    timeout: int = 30,
    env_vars: Optional[dict] = None,
) -> DynamicTraceResult:

    def _sync_run() -> DynamicTraceResult:
        start = time.monotonic()
        stdout_buf = b""
        stderr_buf = b""
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
                io.send(_unescape_stdin(stdin_data).encode())

            try:
                stdout_buf = io.recvrepeat(timeout=min(timeout, 5))
            except EOFError:
                try:
                    stdout_buf = io.buffer.get() if hasattr(io, 'buffer') else b""
                except Exception:
                    stdout_buf = b""
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

            try:
                stderr_buf = io.recvrepeat(timeout=0.5) if hasattr(io, 'recvrepeat') else b""
            except Exception:
                stderr_buf = b""

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
            stderr_head=stderr_buf[:MAX_OUTPUT_BYTES].decode("latin-1") if stderr_buf else "",
            registers=asdict(registers) if registers and hasattr(registers, '__dataclass_fields__') else registers,
            core_dump_hint=_find_core_file(binary_path),
            elapsed_seconds=round(time.monotonic() - start, 3),
        )

    return await asyncio.to_thread(_sync_run)


# ── Tool 2: gdb_breakpoint_read ──────────────────────────────

async def gdb_breakpoint_read(
    binary_path: str,
    args: list[str],
    breakpoint_addr: str,
    breakpoint_type: str = "software",
    memory_reads: list[dict] = None,
    extra_commands: list[str] = None,
    stdin_data: Optional[str] = None,
    continue_count: int = 0,
    use_starti: bool = False,
    env_vars: Optional[dict] = None,
    timeout: int = 30,
) -> BreakpointResult:
    """
    GDB batch mode 断点 + 寄存器/内存/backtrace 读取。

    v0.5: use_starti 参数正式支持（PIE binary + raw 地址断点必须 true）。
    """

    def _sync_run() -> BreakpointResult:
        if memory_reads is None:
            mem_reads = []
        else:
            mem_reads = memory_reads

        actual_count = min(continue_count, MAX_CONTINUE_COUNT) if continue_count > 0 else 0
        stdin_tmpfile = None

        try:
            if stdin_data:
                stdin_tmpfile = tempfile.NamedTemporaryFile(
                    mode="w", suffix=".stdin", delete=False, dir=WORK_DIR
                )
                stdin_tmpfile.write(_unescape_stdin(stdin_data))
                stdin_tmpfile.close()

            cmds = []
            cmds.append("set pagination off")
            cmds.append("set confirm off")

            # ── use_starti: 先映射内存再设断点 ──
            if use_starti:
                args_str = " ".join(f'"{a}"' if " " in a else a for a in args)
                cmds.append("starti")
                # 断点
                bp_cmd_map = {
                    "software":     f"break *{breakpoint_addr}",
                    "hardware":     f"hbreak *{breakpoint_addr}",
                    "read_watch":   f"rwatch *{breakpoint_addr}",
                    "write_watch":  f"watch *{breakpoint_addr}",
                    "access_watch": f"awatch *{breakpoint_addr}",
                }
                cmds.append(bp_cmd_map.get(breakpoint_type, f"break *{breakpoint_addr}"))
                cmds.append("kill")
                if stdin_tmpfile:
                    cmds.append(f"run {args_str} < {stdin_tmpfile.name}")
                else:
                    cmds.append(f"run {args_str}")
            else:
                # 普通模式
                bp_cmd_map = {
                    "software":     f"break *{breakpoint_addr}",
                    "hardware":     f"hbreak *{breakpoint_addr}",
                    "read_watch":   f"rwatch *{breakpoint_addr}",
                    "write_watch":  f"watch *{breakpoint_addr}",
                    "access_watch": f"awatch *{breakpoint_addr}",
                }
                cmds.append(bp_cmd_map.get(breakpoint_type, f"break *{breakpoint_addr}"))

                # continue_count 模式
                if actual_count > 0:
                    cmds.append(f"set $max_hits = {actual_count}")
                    cmds.append("set $hit_count = 0")
                    cmds.append("commands")
                    cmds.append('  set $hit_count = $hit_count + 1')
                    cmds.append('  printf "\\n=== BREAKPOINT HIT #%d ===\\n", $hit_count')
                    if extra_commands:
                        for ec in extra_commands:
                            cmds.append(f"  {ec}")
                    cmds.append("  info registers")
                    cmds.append("  bt 10")
                    for mr in mem_reads:
                        addr = mr.get("address", "0")
                        length = mr.get("length", 32)
                        cmds.append(f"  x/{length}bx {addr}")
                    cmds.append("  if $hit_count >= $max_hits")
                    cmds.append("    quit")
                    cmds.append("  end")
                    cmds.append("  continue")
                    cmds.append("end")

                # run
                args_str = " ".join(f'"{a}"' if " " in a else a for a in args)
                if stdin_tmpfile:
                    cmds.append(f"run {args_str} < {stdin_tmpfile.name}")
                else:
                    cmds.append(f"run {args_str}")

                # 单次模式后续命令
                if actual_count == 0:
                    if extra_commands:
                        cmds.extend(extra_commands)
                    cmds.append("info registers")
                    cmds.append("bt 10")
                    for mr in mem_reads:
                        addr = mr.get("address", "0")
                        length = mr.get("length", 32)
                        cmds.append(f"x/{length}bx {addr}")

            cmds.append("quit")

            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False, dir=WORK_DIR) as f:
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

                if actual_count > 0:
                    all_hits = _parse_multi_hits(output, mem_reads)
                    total_hits = len(all_hits)
                    if total_hits > 0:
                        last = all_hits[-1]
                        return BreakpointResult(
                            hit=True, hit_count=total_hits,
                            registers=last["registers"],
                            memory_dumps=last["memory_dumps"],
                            backtrace=last["backtrace"],
                            all_hits=all_hits,
                            gdb_output=output_truncated,
                            error=None,
                        )
                    else:
                        return BreakpointResult(
                            hit=False, hit_count=0,
                            registers={}, memory_dumps=[], backtrace="",
                            all_hits=[], gdb_output=output_truncated,
                            error="Breakpoint was not hit (continue_count mode)",
                        )
                else:
                    registers = _parse_gdb_registers(output)
                    mem_dumps = _parse_gdb_memory(output, mem_reads)
                    backtrace = _parse_gdb_backtrace(output)
                    hit = ("Breakpoint" in output
                           or "Hardware watchpoint" in output
                           or "watchpoint" in output.lower())
                    return BreakpointResult(
                        hit=hit, hit_count=1 if hit else 0,
                        registers=registers, memory_dumps=mem_dumps,
                        backtrace=backtrace, all_hits=[],
                        gdb_output=output_truncated, error=None,
                    )

            except subprocess.TimeoutExpired:
                return BreakpointResult(
                    hit=False, hit_count=0,
                    registers={}, memory_dumps=[], backtrace="",
                    all_hits=[], gdb_output="",
                    error=f"GDB timed out after {timeout}s",
                )
            except FileNotFoundError:
                return BreakpointResult(
                    hit=False, hit_count=0,
                    registers={}, memory_dumps=[], backtrace="",
                    all_hits=[], gdb_output="",
                    error="GDB not found. Install: apt install gdb",
                )
            except Exception as e:
                return BreakpointResult(
                    hit=False, hit_count=0,
                    registers={}, memory_dumps=[], backtrace="",
                    all_hits=[], gdb_output="",
                    error=f"{type(e).__name__}: {str(e)[:300]}",
                )
            finally:
                os.unlink(script_path)

        finally:
            if stdin_tmpfile and os.path.exists(stdin_tmpfile.name):
                os.unlink(stdin_tmpfile.name)

    return await asyncio.to_thread(_sync_run)


# ── Tool 3: disassemble_bytes (unchanged) ────────────────────

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


# ── Tool 4: get_pie_base (unchanged) ─────────────────────────

async def get_pie_base(
    binary_path: str,
    env_vars: Optional[dict] = None,
    timeout: int = 10,
) -> dict:
    """获取 PIE binary 的 base address。"""

    def _sync_run() -> dict:
        cmds = [
            "set pagination off",
            "set confirm off",
            "starti",
            "info proc mappings",
            "quit",
        ]

        with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False, dir=WORK_DIR) as f:
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
            mappings = []
            base_address = None
            binary_name = os.path.basename(binary_path)

            map_pat = re.compile(
                r'(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+'
                r'(0x[0-9a-fA-F]+)\s+(\S+)\s*(.*)'
            )
            for line in output.split("\n"):
                m = map_pat.match(line.strip())
                if m:
                    start_addr, end_addr, size, offset, perms, obj_file = (
                        m.group(1), m.group(2), m.group(3), m.group(4),
                        m.group(5), m.group(6).strip()
                    )
                    mappings.append({
                        "start": start_addr, "end": end_addr,
                        "size": size, "offset": offset,
                        "perms": perms, "file": obj_file,
                    })
                    if (base_address is None and offset == "0x0"
                            and (binary_name in obj_file or obj_file.endswith(binary_path))):
                        base_address = start_addr

            if base_address is None:
                for mapping in mappings:
                    if mapping["offset"] == "0x0" and "x" in mapping.get("perms", ""):
                        base_address = mapping["start"]
                        break

            if base_address is None and mappings:
                base_address = mappings[0]["start"]

            if base_address is None:
                return {"error": "Could not determine PIE base address", "gdb_output": output[:MAX_GDB_OUTPUT]}

            return {
                "base_address": base_address,
                "mappings": mappings[:10],
                "hint": f"Runtime addr = base + ghidra_offset. Example: if Ghidra shows 0x1234, runtime = {base_address} + 0x1234",
            }

        except subprocess.TimeoutExpired:
            return {"error": f"GDB timed out after {timeout}s"}
        except FileNotFoundError:
            return {"error": "GDB not found. Install: apt install gdb"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)[:300]}"}
        finally:
            os.unlink(script_path)

    return await asyncio.to_thread(_sync_run)


# ── Tool 5: ping (unchanged) ─────────────────────────────────

async def health_check() -> dict:
    """健康检查"""
    def _sync_run() -> dict:
        status = {
            "server": "revagent-dynamic",
            "version": "0.5",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "checks": {},
        }

        gdb_path = shutil.which("gdb")
        if gdb_path:
            try:
                r = subprocess.run(["gdb", "--version"], capture_output=True, text=True, timeout=5)
                version_line = r.stdout.split("\n")[0] if r.stdout else "unknown"
                status["checks"]["gdb"] = {"ok": True, "path": gdb_path, "version": version_line}
            except Exception as e:
                status["checks"]["gdb"] = {"ok": False, "error": str(e)}
        else:
            status["checks"]["gdb"] = {"ok": False, "error": "gdb not found in PATH"}

        try:
            import pwn as _pwn
            ver = getattr(_pwn, '__version__', getattr(_pwn, 'version', 'unknown'))
            status["checks"]["pwntools"] = {"ok": True, "version": str(ver)}
        except Exception as e:
            status["checks"]["pwntools"] = {"ok": False, "error": str(e)}

        try:
            import capstone
            status["checks"]["capstone"] = {"ok": True, "version": capstone.__version__}
        except ImportError:
            status["checks"]["capstone"] = {"ok": False, "error": "not installed"}

        status["checks"]["pid"] = os.getpid()
        status["checks"]["cwd"] = os.getcwd()
        status["checks"]["work_dir"] = WORK_DIR

        all_ok = all(
            c.get("ok", False) for k, c in status["checks"].items()
            if isinstance(c, dict) and "ok" in c
        )
        status["all_ok"] = all_ok
        return status

    return await asyncio.to_thread(_sync_run)


# ── Tool 6: run_gdb_script (v0.5 新增) ───────────────────────

async def run_gdb_script(
    binary_path: str,
    gdb_python_script: str,
    args: list[str] = None,
    stdin_data: Optional[str] = None,
    result_file: str = "/tmp/revagent/gdb_result.txt",
    env_vars: Optional[dict] = None,
    timeout: int = 60,
) -> dict:
    """
    v0.5 新增：一步完成 GDB Python 脚本的写入、执行、结果读取。

    解决的问题：locked_in 中 Agent 每次需要 3-5 次 tool call：
      1. bash heredoc 写脚本到 /tmp/
      2. bash 写输入文件到 /tmp/
      3. bash 执行 gdb --batch
      4. bash 读取结果文件
      5. 解析结果

    现在只需 1 次 tool call。

    参数：
      gdb_python_script: GDB Python 脚本内容（字符串）
        - 脚本应该把结果写到 result_file 路径
        - 脚本中可以用 {BINARY_PATH}, {ARGS}, {STDIN_FILE} 占位符
      result_file: 脚本执行后读取的结果文件路径
      stdin_data: 程序输入（可选，自动写文件并设置 STDIN_FILE 变量）

    返回：
      {
        "gdb_stdout": "...",     # GDB 标准输出（截断到 8KB）
        "gdb_stderr": "...",     # GDB 标准错误（截断到 2KB）
        "gdb_exit_code": 0,
        "result_file_content": "...",  # result_file 的内容（截断到 32KB）
        "result_file_lines": 42,       # 结果文件行数
        "elapsed_seconds": 3.2,
      }
    """

    def _sync_run() -> dict:
        start = time.monotonic()
        stdin_file_path = None
        script_file_path = None

        try:
            os.makedirs(os.path.dirname(result_file) or WORK_DIR, exist_ok=True)

            # 写 stdin 文件
            if stdin_data:
                stdin_file_path = os.path.join(WORK_DIR, "gdb_script_stdin.txt")
                with open(stdin_file_path, "w") as f:
                    f.write(_unescape_stdin(stdin_data))

            # 替换占位符
            args_list = args or []
            args_str = " ".join(f'"{a}"' if " " in a else a for a in args_list)
            script_content = gdb_python_script
            script_content = script_content.replace("{BINARY_PATH}", binary_path)
            script_content = script_content.replace("{ARGS}", args_str)
            script_content = script_content.replace("{STDIN_FILE}", stdin_file_path or "")
            script_content = script_content.replace("{RESULT_FILE}", result_file)

            # 写 GDB Python 脚本
            script_file_path = os.path.join(WORK_DIR, f"gdb_script_{int(time.time())}.py")
            with open(script_file_path, "w") as f:
                f.write(script_content)

            # 执行
            run_env = os.environ.copy()
            if env_vars:
                run_env.update(env_vars)

            proc = subprocess.run(
                ["gdb", "--batch", "-x", script_file_path, binary_path],
                capture_output=True, text=True, timeout=timeout, env=run_env,
            )

            # 读取结果文件
            result_content = ""
            result_lines = 0
            if os.path.exists(result_file):
                with open(result_file, "r") as f:
                    result_content = f.read(MAX_GDB_SCRIPT_OUTPUT)
                    result_lines = result_content.count("\n")
                    if len(result_content) >= MAX_GDB_SCRIPT_OUTPUT:
                        result_content += f"\n... [TRUNCATED at {MAX_GDB_SCRIPT_OUTPUT} bytes]"

            return {
                "gdb_stdout": proc.stdout[-MAX_OUTPUT_BYTES:] if proc.stdout else "",
                "gdb_stderr": proc.stderr[-2048:] if proc.stderr else "",
                "gdb_exit_code": proc.returncode,
                "result_file_content": result_content,
                "result_file_lines": result_lines,
                "elapsed_seconds": round(time.monotonic() - start, 3),
            }

        except subprocess.TimeoutExpired:
            return {
                "error": f"GDB script timed out after {timeout}s",
                "elapsed_seconds": round(time.monotonic() - start, 3),
            }
        except FileNotFoundError:
            return {"error": "GDB not found. Install: apt install gdb"}
        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)[:500]}"}
        finally:
            if script_file_path and os.path.exists(script_file_path):
                os.unlink(script_file_path)
            # 不删除 stdin 和 result 文件（Agent 可能需要再次读取）

    return await asyncio.to_thread(_sync_run)


# ── Tool 7: patch_binary (v0.5 新增) ─────────────────────────

async def patch_binary(
    binary_path: str,
    patches: list[dict],
    output_path: Optional[str] = None,
) -> dict:
    """
    v0.5 新增：二进制 patch 工具。

    用途：NOP 反调试代码（如 tomb 的自定义 puts shellcode）、修改跳转等。

    参数：
      patches: 补丁列表，每项：
        {"offset": 0x1234, "bytes": "90909090"}  # 指定 hex bytes
        {"offset": 0x1234, "length": 4}          # NOP 填充（自动用 0x90）
      output_path: 输出路径（默认在原文件旁加 _patched 后缀）

    自动备份原文件到 binary_path + ".bak"
    """

    def _sync_run() -> dict:
        if not os.path.isfile(binary_path):
            return {"error": f"File not found: {binary_path}"}

        # 确定输出路径
        if output_path:
            out_path = output_path
        else:
            base, ext = os.path.splitext(binary_path)
            out_path = f"{base}_patched{ext}"

        try:
            # 读取原始文件
            with open(binary_path, "rb") as f:
                data = bytearray(f.read())

            original_size = len(data)
            applied = []

            for i, patch in enumerate(patches):
                offset = patch.get("offset")
                if offset is None:
                    return {"error": f"Patch {i}: missing 'offset'"}

                if isinstance(offset, str):
                    offset = int(offset, 16) if offset.startswith("0x") else int(offset)

                if offset < 0 or offset >= original_size:
                    return {"error": f"Patch {i}: offset 0x{offset:x} out of range (file size: 0x{original_size:x})"}

                if "bytes" in patch:
                    patch_bytes = bytes.fromhex(patch["bytes"].replace(" ", ""))
                elif "length" in patch:
                    patch_bytes = b"\x90" * patch["length"]  # NOP fill
                else:
                    return {"error": f"Patch {i}: must specify 'bytes' or 'length'"}

                if offset + len(patch_bytes) > original_size:
                    return {"error": f"Patch {i}: patch extends beyond file end"}

                # 记录原始字节
                original_bytes = data[offset:offset + len(patch_bytes)]
                data[offset:offset + len(patch_bytes)] = patch_bytes

                applied.append({
                    "offset": f"0x{offset:x}",
                    "length": len(patch_bytes),
                    "original": original_bytes.hex(),
                    "patched": patch_bytes.hex(),
                })

            # 备份原文件
            bak_path = binary_path + ".bak"
            if not os.path.exists(bak_path):
                shutil.copy2(binary_path, bak_path)

            # 写 patched 文件
            with open(out_path, "wb") as f:
                f.write(data)

            # 保留执行权限
            os.chmod(out_path, os.stat(binary_path).st_mode)

            return {
                "output_path": out_path,
                "backup_path": bak_path,
                "file_size": original_size,
                "patches_applied": len(applied),
                "details": applied,
            }

        except Exception as e:
            return {"error": f"{type(e).__name__}: {str(e)[:500]}"}

    return await asyncio.to_thread(_sync_run)


# ═══════════════════════════════════════════════════════════════
# 5. MCP Server
# ═══════════════════════════════════════════════════════════════

app = Server("revagent-dynamic")


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="run_dynamic_trace",
            description=(
                "运行 ELF 二进制并捕获行为。返回 JSON：退出原因、stdout、stderr、崩溃时寄存器。"
                "支持 env_vars 注入环境变量（如 OPENSSL_CONF=/dev/null）。"
                "【安全】内置 120 秒硬超时。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "ELF 文件绝对路径"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "命令行参数", "default": []},
                    "stdin_data": {"type": "string", "description": "stdin 输入数据（支持 \\n \\t \\r \\0 转义）", "default": None},
                    "timeout": {"type": "integer", "description": "最大秒数（上限120）", "default": 10},
                    "env_vars": {"type": "object", "description": "环境变量", "default": {}},
                },
                "required": ["binary_path"],
            },
        ),

        Tool(
            name="gdb_breakpoint_read",
            description=(
                "GDB batch mode：在指定地址下断点/watchpoint，命中后读寄存器、内存、backtrace。\n"
                "5 种断点类型：software, hardware, read_watch, write_watch, access_watch。\n"
                "extra_commands：断点命中后执行自定义 GDB 命令（如 set $rax=0 绕过反调试）。\n"
                "stdin_data：程序需要 stdin 输入时使用（支持 \\n 等转义）。\n"
                "continue_count：断点命中 N 次，每次收集寄存器/内存/bt。注意：N>30 时输出可能超限，改用 run_gdb_script。\n"
                "use_starti：PIE binary + raw 地址断点时必须 true（先映射内存再设断点）。\n"
                "核心用途：获取运行时状态（加密密钥、VM 内存、反调试后的全局变量）。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "ELF 文件绝对路径"},
                    "args": {"type": "array", "items": {"type": "string"}, "description": "命令行参数", "default": []},
                    "breakpoint_addr": {"type": "string", "description": "地址（如 '0x403300'）或表达式（如 '*main+897'）"},
                    "breakpoint_type": {
                        "type": "string", "description": "断点类型",
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
                        "type": "array", "items": {"type": "string"},
                        "description": "断点命中后执行的自定义 GDB 命令",
                        "default": [],
                    },
                    "stdin_data": {
                        "type": "string",
                        "description": "程序的 stdin 输入（支持 \\n \\t \\r \\0 转义）",
                        "default": None,
                    },
                    "continue_count": {
                        "type": "integer",
                        "description": "断点命中次数。N>30 时建议改用 run_gdb_script 避免输出超限。上限200。",
                        "default": 0,
                    },
                    "use_starti": {
                        "type": "boolean",
                        "description": "PIE binary + raw 地址断点必须 true（starti → 设断点 → kill → run）",
                        "default": False,
                    },
                    "env_vars": {"type": "object", "description": "环境变量", "default": {}},
                    "timeout": {"type": "integer", "description": "GDB 最大秒数（上限120）", "default": 15},
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

        Tool(
            name="get_pie_base",
            description=(
                "获取 PIE binary 的运行时 base address。\n"
                "方法：GDB starti → info proc mappings → 解析基地址。\n"
                "用途：运行时地址 = base + Ghidra 中的偏移。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "ELF 文件绝对路径"},
                    "env_vars": {"type": "object", "description": "环境变量", "default": {}},
                    "timeout": {"type": "integer", "description": "最大秒数", "default": 10},
                },
                "required": ["binary_path"],
            },
        ),

        Tool(
            name="ping",
            description=(
                "健康检查：验证 MCP server 存活、GDB/pwntools/capstone 可用性。\n"
                "超时或失败说明 SSH 连接已断开。"
            ),
            inputSchema={"type": "object", "properties": {}},
        ),

        Tool(
            name="run_gdb_script",
            description=(
                "【v0.5 新增】一步完成 GDB Python 脚本的写入 → 执行 → 结果读取。\n"
                "解决的问题：不再需要 3-5 次 tool call 手动写脚本/执行/读文件。\n\n"
                "用法：传入 GDB Python 脚本内容，脚本应将结果写到 result_file 路径。\n"
                "脚本中可用占位符：{BINARY_PATH}, {ARGS}, {STDIN_FILE}, {RESULT_FILE}。\n\n"
                "适用场景：\n"
                "  - continue_count > 30 时（避免输出超限）\n"
                "  - 多断点协作（如同时追踪 MEM_STORE 和 XOR handler）\n"
                "  - 条件过滤（只记录满足条件的命中）\n"
                "  - 复杂数据收集（每次命中计算衍生值）\n\n"
                "注意：脚本中不要用 f-string（和外层 Python 冲突），用 % 格式化。\n"
                "结果文件最大读取 32KB，超出截断。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "ELF 文件绝对路径"},
                    "gdb_python_script": {
                        "type": "string",
                        "description": (
                            "GDB Python 脚本内容。脚本应把结果写到 result_file。\n"
                            "可用占位符：{BINARY_PATH}, {ARGS}, {STDIN_FILE}, {RESULT_FILE}"
                        ),
                    },
                    "args": {"type": "array", "items": {"type": "string"}, "description": "程序命令行参数", "default": []},
                    "stdin_data": {"type": "string", "description": "程序 stdin 输入（自动写文件）", "default": None},
                    "result_file": {
                        "type": "string",
                        "description": "结果文件路径（脚本写入，tool 自动读取返回）",
                        "default": "/tmp/revagent/gdb_result.txt",
                    },
                    "env_vars": {"type": "object", "description": "环境变量", "default": {}},
                    "timeout": {"type": "integer", "description": "最大秒数（上限120）", "default": 60},
                },
                "required": ["binary_path", "gdb_python_script"],
            },
        ),

        Tool(
            name="patch_binary",
            description=(
                "【v0.5 新增】二进制 patch：NOP 反调试代码、修改字节。\n"
                "自动备份原文件到 .bak，输出到 _patched 文件。\n\n"
                "用法：指定 patches 列表，每项包含 offset + bytes/length。\n"
                "  {\"offset\": \"0x1234\", \"bytes\": \"90909090\"}  # 写入指定字节\n"
                "  {\"offset\": \"0x1234\", \"length\": 4}            # NOP 填充\n\n"
                "典型用途：NOP 掉 ptrace 反调试、patch 跳转条件、替换函数调用。"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "binary_path": {"type": "string", "description": "ELF 文件绝对路径"},
                    "patches": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "offset": {"type": ["string", "integer"], "description": "文件偏移（十六进制字符串或整数）"},
                                "bytes": {"type": "string", "description": "替换的十六进制字节（与 length 二选一）"},
                                "length": {"type": "integer", "description": "NOP 填充长度（与 bytes 二选一）"},
                            },
                            "required": ["offset"],
                        },
                        "description": "补丁列表",
                    },
                    "output_path": {
                        "type": "string",
                        "description": "输出路径（默认 binary_path_patched）",
                        "default": None,
                    },
                },
                "required": ["binary_path", "patches"],
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
            r = await execute_binary(
                bp, arguments.get("args", []), arguments.get("stdin_data"),
                min(arguments.get("timeout", 10), MAX_EXECUTION_TIMEOUT),
                arguments.get("env_vars"),
            )
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
                arguments.get("stdin_data"),
                arguments.get("continue_count", 0),
                arguments.get("use_starti", False),       # v0.5
                arguments.get("env_vars"),
                min(arguments.get("timeout", 15), MAX_EXECUTION_TIMEOUT),
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

    elif name == "get_pie_base":
        bp = arguments.get("binary_path", "")
        if not bp or not os.path.isfile(bp):
            return [TextContent(type="text", text=json.dumps({"error": f"File not found: {bp}"}))]
        try:
            r = await get_pie_base(
                bp, arguments.get("env_vars"),
                min(arguments.get("timeout", 10), MAX_EXECUTION_TIMEOUT),
            )
            return [TextContent(type="text", text=json.dumps(r, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)[:500]}))]

    elif name == "ping":
        try:
            r = await health_check()
            return [TextContent(type="text", text=json.dumps(r, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)[:500]}))]

    elif name == "run_gdb_script":
        bp = arguments.get("binary_path", "")
        if not bp or not os.path.isfile(bp):
            return [TextContent(type="text", text=json.dumps({"error": f"File not found: {bp}"}))]
        script = arguments.get("gdb_python_script", "")
        if not script:
            return [TextContent(type="text", text=json.dumps({"error": "gdb_python_script required"}))]
        try:
            r = await run_gdb_script(
                bp, script,
                arguments.get("args", []),
                arguments.get("stdin_data"),
                arguments.get("result_file", "/tmp/revagent/gdb_result.txt"),
                arguments.get("env_vars"),
                min(arguments.get("timeout", 60), MAX_EXECUTION_TIMEOUT),
            )
            return [TextContent(type="text", text=json.dumps(r, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)[:500]}))]

    elif name == "patch_binary":
        bp = arguments.get("binary_path", "")
        if not bp or not os.path.isfile(bp):
            return [TextContent(type="text", text=json.dumps({"error": f"File not found: {bp}"}))]
        patches = arguments.get("patches", [])
        if not patches:
            return [TextContent(type="text", text=json.dumps({"error": "patches list required"}))]
        try:
            r = await patch_binary(bp, patches, arguments.get("output_path"))
            return [TextContent(type="text", text=json.dumps(r, indent=2, ensure_ascii=False))]
        except Exception as e:
            return [TextContent(type="text", text=json.dumps({"error": str(e)[:500]}))]

    return [TextContent(type="text", text=json.dumps({"error": f"Unknown tool: {name}"}))]


# ═══════════════════════════════════════════════════════════════
# 6. 入口
# ═══════════════════════════════════════════════════════════════

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
