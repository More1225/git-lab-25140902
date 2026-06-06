# 实验报告：基于 ReAct 智能体与 angr 的自动化逆向分析

## 工具封装

本工程将 angr 封装为可被 Agent 调用的工具：

- `inspect_target()`：读取目标程序装载信息、导入函数与关键字符串，给 ReAct 循环提供语义锚点。
- `explore(max_steps=300)`：构造符号 stdin，使用 angr `SimulationManager.explore` 搜索包含 `Success! Flag is found.` 的状态，同时避开 `trapped` 与 `Wrong password!` 输出路径。
- `solve_input()`：在成功状态中求解符号输入的具体模型，得到可用密码。
- `validate_solution(password)`：用求得的输入实际运行目标程序，检查输出是否包含成功信息。

运行日志见 `logs/run.txt`，包含 4 轮完整的 Thought -> Action -> Observation。

## 实验结果

angr 求得的最小有效输入为：

```text
AZcE
```

原因是目标检查要求：

- `input[0] == 'A'`
- `input[1] == 'Z'`
- `(input[2] ^ 0x12) == 'q'`，因此 `input[2] == 'c'`
- `(input[3] + 3) == 'H'`，因此 `input[3] == 'E'`

## 思考题

在本实验中，LLM 主要承担任务规划与语义编排角色。它不直接枚举路径或求解约束，而是根据程序中的高层语义信息选择搜索目标，例如优先到达包含 `Success!` 的输出路径，并主动避开 `trapped` 或死循环相关路径。

这种语义层面的引导可以缓解纯符号执行的搜索空间问题：angr 负责严密地执行路径约束与模型求解，LLM 则负责把“应该找什么、应该避开什么、何时求解输入”组织成若干工具调用。两者结合后，符号执行不必盲目探索全部路径，而是围绕成功字符串和危险分支进行定向搜索。
