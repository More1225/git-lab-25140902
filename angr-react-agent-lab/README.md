# ReAct Agent With angr

This lab builds a small `crackme` target and solves its password with a
ReAct-style agent. The agent exposes angr as tools, records at least three
Thought -> Action -> Observation rounds, and writes the solved input.

## Build

Preferred:

```bash
gcc crackme.c -o crackme
```

On this Windows host, GCC was not on `PATH`, so the checked-in Linux x86_64 ELF
was built with a portable Zig compiler:

```powershell
$env:ZIG_GLOBAL_CACHE_DIR="$PWD\tools\zig-global-cache"
$env:ZIG_LOCAL_CACHE_DIR="$PWD\tools\zig-local-cache"
.\tools\zig-windows-x86_64-0.13.0\zig.exe cc -target x86_64-linux-gnu -O0 -fno-stack-protector -no-pie crackme.c -o crackme
```

The portable Zig directory and Python virtual environment are intentionally not
committed.

## Run

```bash
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\python react_angr_agent.py
```

Outputs:

- `logs/run.txt`: complete ReAct transcript
- `output/solution.json`: solved input and path metadata
- `report.md`: short answer to the thinking question
