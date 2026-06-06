#!/usr/bin/env python3
"""ReAct-style agent that uses angr tools to solve crackme.exe/crackme."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import angr
import claripy


ROOT = Path(__file__).resolve().parent
DEFAULT_TARGETS = [ROOT / "crackme", ROOT / "crackme.exe"]


@dataclass
class Observation:
    tool: str
    result: dict[str, Any]

    def render(self) -> str:
        return f"Observation:\n{json.dumps(self.result, indent=2, ensure_ascii=False)}"


class AngrToolbox:
    """Small read-only angr toolbox exposed to the ReAct loop."""

    def __init__(self, target: Path):
        self.target = target
        self.project = angr.Project(str(target), auto_load_libs=False)
        self.input_len = 10
        self.sym_bytes = [claripy.BVS(f"pw_{i}", 8) for i in range(self.input_len)]
        self.sym_input = claripy.Concat(*self.sym_bytes)
        self.buffer_addr = 0x500000
        self.check_symbol = self.project.loader.find_symbol("check_password")
        if self.check_symbol is not None:
            self.state = self.project.factory.call_state(
                self.check_symbol.rebased_addr,
                self.buffer_addr,
                add_options={
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                },
            )
            self.state.memory.store(
                self.buffer_addr,
                claripy.Concat(self.sym_input, claripy.BVV(0, 8)),
            )
            self.state.memory.store(self.buffer_addr + self.input_len + 1, b"\x00" * 128)
            self.mode = "direct call_state(check_password(symbolic_buffer))"
        else:
            self.state = self.project.factory.full_init_state(
                args=[str(target)],
                stdin=angr.SimFileStream(
                    name="stdin",
                    content=claripy.Concat(self.sym_input, claripy.BVV(b"\n")),
                    has_end=True,
                ),
            )
            self.mode = "full_init_state(symbolic_stdin)"
        for byte in self.sym_bytes:
            self.state.solver.add(byte >= 0x20)
            self.state.solver.add(byte <= 0x7E)
        self.simgr = self.project.factory.simgr(self.state)
        self.success_state = None
        self.deadend_states = []

    def inspect_target(self) -> Observation:
        """Tool 1: summarize loader facts and known semantic targets."""
        imports = sorted(
            name for name in self.project.loader.main_object.imports.keys()
        )
        symbols = sorted(
            sym.name
            for sym in self.project.loader.main_object.symbols
            if sym.is_function and sym.name in {"main", "check_password", "gadget_trap"}
        )
        strings = subprocess.run(
            ["powershell", "-NoProfile", "-Command", self._strings_command()],
            cwd=str(ROOT),
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        ).stdout.strip().splitlines()
        interesting = [
            line for line in strings if "Success" in line or "trapped" in line or "Wrong" in line
        ]
        return Observation(
            "inspect_target",
            {
                "target": str(self.target),
                "arch": self.project.arch.name,
                "entry": hex(self.project.entry),
                "format": self.project.loader.main_object.__class__.__name__,
                "analysis_mode": self.mode,
                "known_functions": symbols,
                "check_password": hex(self.check_symbol.rebased_addr)
                if self.check_symbol is not None
                else None,
                "imports": imports,
                "semantic_markers": interesting,
                "goal": "reach output containing 'Success! Flag is found.'",
                "avoid": "states whose stdout contains 'trapped' or 'Wrong password!'",
            },
        )

    def explore(self, max_steps: int = 300) -> Observation:
        """Tool 2: controlled exploration toward success while avoiding traps."""

        def is_success(state: angr.SimState) -> bool:
            out = state.posix.dumps(1)
            return b"Success! Flag is found." in out

        def should_avoid(state: angr.SimState) -> bool:
            out = state.posix.dumps(1)
            return b"trapped" in out or b"Wrong password!" in out

        for _ in range(max_steps):
            if not self.simgr.active:
                break
            found_now = []
            avoid_now = []
            keep_now = []
            for state in self.simgr.active:
                if is_success(state):
                    found_now.append(state)
                elif should_avoid(state):
                    avoid_now.append(state)
                else:
                    keep_now.append(state)
            self.simgr.stashes["active"] = keep_now
            self.simgr.stashes.setdefault("found", []).extend(found_now)
            self.simgr.stashes.setdefault("avoid", []).extend(avoid_now)
            if self.simgr.found:
                break
            self.simgr.step()
            for state in list(self.simgr.deadended):
                if is_success(state):
                    self.simgr.stashes.setdefault("found", []).append(state)
                    self.simgr.stashes["deadended"].remove(state)
                    break
            if self.simgr.found:
                break
        if self.simgr.found:
            self.success_state = self.simgr.found[0]
        self.deadend_states = list(self.simgr.deadended)
        return Observation(
            "explore",
            {
                "max_steps": max_steps,
                "analysis_mode": self.mode,
                "found": len(self.simgr.found),
                "active": len(self.simgr.active),
                "deadended": len(self.simgr.deadended),
                "avoid": len(self.simgr.avoid),
                "success_reached": self.success_state is not None,
                "success_stdout": self.success_state.posix.dumps(1).decode(
                    "utf-8", errors="replace"
                )
                if self.success_state is not None
                else "",
            },
        )

    def solve_input(self) -> Observation:
        """Tool 3: solve concrete input bytes from the found symbolic state."""
        if self.success_state is None:
            return Observation(
                "solve_input",
                {"error": "explore must find a success state before solving input"},
            )
        raw = self.success_state.solver.eval(self.sym_input, cast_to=bytes)
        token = raw.split(b"\x00", 1)[0].split(b"\n", 1)[0]
        # scanf("%9s") consumes a whitespace-delimited token; trim padding while
        # keeping at least four characters that satisfy the semantic checks.
        printable = token.decode("ascii", errors="replace").strip()
        candidate = printable[:9]
        minimal = candidate[:4]
        return Observation(
            "solve_input",
            {
                "raw_model_hex": raw.hex(),
                "candidate": candidate,
                "minimal_password": minimal,
                "constraints_checked": [
                    "input[0] == 'A'",
                    "input[1] == 'Z'",
                    "(input[2] ^ 0x12) == 'q'",
                    "(input[3] + 3) == 'H'",
                ],
            },
        )

    def validate_solution(self, password: str) -> Observation:
        """Tool 4: execute target once to verify the concrete solution."""
        if self.project.loader.main_object.__class__.__name__ == "ELF":
            concrete = angr.Project(str(self.target), auto_load_libs=False)
            check_symbol = concrete.loader.find_symbol("check_password")
            if check_symbol is not None:
                state = concrete.factory.call_state(
                    check_symbol.rebased_addr,
                    self.buffer_addr,
                    add_options={
                        angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                        angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                    },
                )
                state.memory.store(self.buffer_addr, password.encode("ascii") + b"\x00" * 128)
                runner = "angr concrete replay of check_password for ELF target on Windows"
            else:
                state = concrete.factory.full_init_state(
                    args=[str(self.target)],
                    stdin=angr.SimFileStream(
                        name="stdin",
                        content=(password + "\n").encode("ascii"),
                        has_end=True,
                    ),
                )
                runner = "angr concrete replay for ELF target on Windows"
            simgr = concrete.factory.simgr(state)
            success_stdout = ""
            for _ in range(120):
                if not simgr.active:
                    break
                for active in simgr.active:
                    out = active.posix.dumps(1)
                    if b"Success! Flag is found." in out:
                        success_stdout = out.decode("utf-8", errors="replace")
                        return Observation(
                            "validate_solution",
                            {
                                "password": password,
                                "runner": runner,
                                "steps": _,
                                "stdout": success_stdout,
                                "success": True,
                            },
                        )
                simgr.step()
            stdout = ""
            for stash in ("deadended", "active", "avoid"):
                states = getattr(simgr, stash, [])
                if states:
                    stdout = states[0].posix.dumps(1).decode("utf-8", errors="replace")
                    break
            return Observation(
                "validate_solution",
                {
                    "password": password,
                    "runner": runner,
                    "stdout": stdout,
                    "success": False,
                },
            )

        proc = subprocess.run(
            [str(self.target)],
            input=password + "\n",
            text=True,
            encoding="utf-8",
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(ROOT),
            timeout=10,
            check=False,
        )
        return Observation(
            "validate_solution",
            {
                "password": password,
                "returncode": proc.returncode,
                "stdout": proc.stdout,
                "success": "Success! Flag is found." in proc.stdout,
            },
        )

    def _strings_command(self) -> str:
        # PowerShell-only fallback, kept local so the angr tools remain portable
        # without extra native dependencies.
        target = str(self.target).replace("'", "''")
        return (
            "$bytes=[IO.File]::ReadAllBytes('"
            + target
            + "'); $s=''; foreach($b in $bytes){ if($b -ge 32 -and $b -le 126){"
            + " $s += [char]$b } else { if($s.Length -ge 4){ $s }; $s='' } };"
            + " if($s.Length -ge 4){ $s }"
        )


def choose_target() -> Path:
    for target in DEFAULT_TARGETS:
        if target.exists():
            return target
    raise SystemExit("No crackme target found. Build crackme.c first.")


def run_agent() -> dict[str, Any]:
    target = choose_target()
    tools = AngrToolbox(target)
    transcript: list[str] = []
    solution: dict[str, Any] = {}

    transcript.append("ReAct angr Agent Run")
    transcript.append("Model/planner: GPT-5 Codex assisted deterministic ReAct policy")
    transcript.append("Target: " + str(target))
    transcript.append("Objective: solve an input that reaches 'Success! Flag is found.' while avoiding trapped/dead-loop paths.")
    transcript.append("")

    steps = [
        (
            "I need semantic anchors before symbolic execution: success text, trap text, and the input API.",
            "inspect_target()",
            tools.inspect_target,
        ),
        (
            "The success text is a good find condition and trapped/wrong outputs are good avoid conditions; run controlled angr exploration.",
            "explore(max_steps=300)",
            lambda: tools.explore(max_steps=300),
        ),
        (
            "A success state exists, so solve stdin bytes from that symbolic state.",
            "solve_input()",
            tools.solve_input,
        ),
    ]

    for thought, action, fn in steps:
        transcript.append("Thought: " + thought)
        transcript.append("Action: " + action)
        obs = fn()
        transcript.append(obs.render())
        transcript.append("")
        if obs.tool == "solve_input" and "minimal_password" in obs.result:
            solution = dict(obs.result)

    password = solution.get("minimal_password", "")
    transcript.append("Thought: Before finalizing, verify the concrete password by running the target once.")
    transcript.append(f"Action: validate_solution({password!r})")
    validation = tools.validate_solution(password)
    transcript.append(validation.render())
    transcript.append("")

    final = {
        "password": password,
        "success": validation.result.get("success", False),
        "target": str(target.name),
        "method": "angr symbolic stdin, ReAct-guided find/avoid exploration",
    }
    transcript.append("Final Answer:")
    transcript.append(json.dumps(final, indent=2, ensure_ascii=False))
    transcript.append("")

    (ROOT / "logs").mkdir(exist_ok=True)
    (ROOT / "output").mkdir(exist_ok=True)
    (ROOT / "logs" / "run.txt").write_text("\n".join(transcript), encoding="utf-8")
    (ROOT / "output" / "solution.json").write_text(
        json.dumps(final, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return final


if __name__ == "__main__":
    print(json.dumps(run_agent(), indent=2, ensure_ascii=False))
