# ReAct Agent Static Binary Analysis

This project analyzes `targets/challenge`, a stripped Linux x86_64 ELF, with a
deterministic ReAct loop. The required output files are:

- `vuln.json`
- `logs/run.txt`
- `agent.py` plus `requirements.txt`

## Tool Paths

The checked-in log was generated with portable tool installs on this machine:

- `D:\Codex\dailyword\course\binary-react-agent\tools\radare2-6.1.6-w64\bin\radare2.exe`
- `D:\Codex\dailyword\course\binary-react-agent\tools\ghidra_12.1_PUBLIC\support\analyzeHeadless.bat`
- `D:\Codex\dailyword\course\binary-react-agent\tools\jdk-21.0.11+10`

Large tool directories are intentionally not committed. To rerun from a fresh
clone, install radare2, Ghidra, and JDK 21 under `tools/` with the same layout,
put their executables on `PATH`, or set:

```powershell
$env:R2_BIN = "C:\path\to\radare2.exe"
$env:GHIDRA_HEADLESS = "C:\path\to\ghidra\support\analyzeHeadless.bat"
$env:JAVA_HOME = "C:\path\to\jdk-21"
```

`logs/run.txt` was generated with real radare2 and Ghidra headless calls. No API
key is required.

## Run

```powershell
python agent.py --target targets/challenge --log logs/run.txt --out vuln.json
```

The agent writes the final structured answer to `vuln.json` and records the full
Thought -> Action -> Observation transcript in `logs/run.txt`.
