<div align="center">

# BenchShield

**面向 AI Agent 基准测试的防作弊审计与隔离评测沙箱。**

[![CI](https://github.com/1690940255ran-dot/benchshield/actions/workflows/ci.yml/badge.svg)](https://github.com/1690940255ran-dot/benchshield/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![零依赖](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#设计说明)
[![License: MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-108%20passing-brightgreen.svg)](tests/)

[English](README.md) · [简体中文](README.zh-CN.md)

</div>

---

## 问题背景

2026 年 4 月，UC Berkeley RDI 团队证明：一个**没有任何任务解决能力**的智能体，可以在八大主流 Agent 基准（SWE-bench Verified、Terminal-Bench、WebArena、GAIA 等）上拿到接近满分——不是靠解题，而是**攻击评测流程本身**：从工作区读出金标答案、覆写检查器、给 `eval()` 返回一个真值表达式……

如果你在构建或维护一个 Agent 基准，问题不是你的评测框架**会不会**被作弊，而是**有多容易**，以及**你怎么知道**。

## BenchShield 做什么

BenchShield 把这项研究落地成六个可组合的工具：

| 工具 | 作用 |
|---|---|
| `scan` | 静态审计器，检测基准项目中的**七类漏洞模式**（V1–V7），带文件/行号证据 |
| `runtime` | `SecureRunner`——加固版评测运行时，强制进程隔离、每任务独立工作区、篡改日志；`DockerRunner`——同样的信任模型，评测器封进一个锁定容器 |
| `adapters` | SWE-bench / Terminal-Bench 数据接入：真实基准数据转为任务，金标答案绝不进入智能体视野 |
| `redteam` | 零能力攻击智能体（攻击载荷库），用来**证明**某个评测框架确实可被攻破——以及你的防御确实有效 |
| `judge` | LLM 语义评判，自带注入筛查、提示词消毒与 fail-closed 判定 |
| `checklist` | **Agent-Eval Checklist（C1–C10）**评分，给出 A–F 等级，可直接接入 CI |

零第三方依赖，Python 3.10+，MIT 协议。

## 30 秒演示

```
$ python -m benchshield demo --n 50

Runner      Agent                             Solved    Rate  Notes
vulnerable  honest-solver                     50/50   100.0%
vulnerable  zero-cap [V2 peek-answers]        50/50   100.0%  V2：从共享工作区 tasks.json 读出金标答案
vulnerable  zero-cap [V3 eval-always-true]    50/50   100.0%  V3：响应被当作代码执行（checker 拒绝后 eval() 兜底接受任意 Python 表达式）
vulnerable  zero-cap [V7 overwrite-checker]   50/50   100.0%  V7：checker.py 被智能体在 50/50 个任务上篡改
secure      honest-solver                     50/50   100.0%
secure      zero-cap [V2 peek-answers]         0/50     0.0%  被阻断：智能体工作区内没有金标答案
secure      zero-cap [V3 eval-always-true]     0/50     0.0%  被阻断：响应按纯文本解析，绝不作为代码执行
secure      zero-cap [V7 overwrite-checker]    0/50     0.0%  50 次篡改尝试被记录并中和
```

同样的智能体、同样的任务，唯一的差别是评测框架本身——而这个差别值 100 分的"能力"虚报。这就是 Berkeley RDI 的结论，在本地 30 秒内复现。

## 安装

```bash
git clone https://github.com/1690940255ran-dot/benchshield.git
cd benchshield
pip install -e .          # 可选；直接在仓库根目录运行也可以
```

## 快速上手

```bash
# 1. 审计一个基准项目（发现 critical 级问题退出码为 1，可直接接入 CI）
python -m benchshield scan examples/vulnerable_bench

# 2. 观看零能力智能体在易攻破框架上拿 100%、在安全框架上拿 0%
python -m benchshield demo

# 3. 导出 50 任务的 mini 基准，用于你自己的实验
python -m benchshield export-bench --n 50 --seed 42 --out tasks.json
```

在自带的「刻意易攻破」演示基准上的真实 `scan` 输出：

```
$ python -m benchshield scan examples/vulnerable_bench

BenchShield scan of examples/vulnerable_bench
  files scanned : 3
  findings      : 8 (critical 3, high 4, medium 1, info 0)

  [CRITICAL] V7 TRUST-OUT    run_eval.py:38  spec_from_file_location() references an agent-writable path or variable
  [CRITICAL] V3 EVAL-CALL    run_eval.py:46  eval() called on non-literal input
  [CRITICAL] V2 DATA-LEAK    tasks.json:1  20 record(s) with gold answers (gold answers shipped next to prompts)
  [HIGH    ] V1 ENV-SHARED   bench_config.json:1  agent workspace and evaluator directory share a path or parent
  [HIGH    ] V1 ENV-NET      bench_config.json:1  network egress allowed for the agent during tasks
  [HIGH    ] V6 NO-CHECK     run_eval.py:21  check() can return True without validating
  [HIGH    ] V4 JUDGE-INJECT run_eval.py:33  LLM-judge prompt interpolates agent-controlled text unsanitized
  [MEDIUM  ] V5 WEAK-MATCH   run_eval.py:28  substring containment used for answer validation

Agent-Eval Checklist grade: F (failed: C1, C2, C3, C4, C5, C6, C7, C8)
```

因为发现 critical 级问题时退出码为 `1`，可以直接放进 CI 当门禁。

## 七类漏洞模式

| 类别 | 模式 | 扫描规则 | 严重度 |
|---|---|---|---|
| V1 | 智能体与评测器之间无隔离（共享目录、网络出口开放） | `ENV-SHARED`、`ENV-NET` | high |
| V2 | 金标答案随测试一起下发 | `DATA-LEAK` | critical |
| V3 | 对不可信输入调用 `eval()`/`exec()` | `EVAL-CALL` | critical |
| V4 | LLM 评判器未对输入做消毒 | `JUDGE-INJECT` | high |
| V5 | 弱字符串匹配（子串包含） | `WEAK-MATCH` | medium |
| V6 | 验证逻辑实际上没有做校验 | `NO-CHECK` | high |
| V7 | 评测器信任不可信代码/文件（pytest 钩子模式） | `TRUST-OUT` | critical |

扫描器是启发式的（Python AST 分析 + JSON 配置约定）。它对七类模式做到了无漏报，但所有发现仍建议人工复核。

## Agent-Eval Checklist

| # | 要求 | 由谁落实 |
|---|---|---|
| C1 | 智能体与评测器环境隔离 | `SecureRunner`：评测器跑在独立进程 |
| C2 | 任务执行期间禁止智能体网络出口 | `netguard`：智能体执行期间运行时强制阻断 socket/DNS |
| C3 | 金标答案绝不可被智能体访问 | `SecureRunner`：金标从不写入工作区 |
| C4 | 不对智能体字符串调用 `eval()`/`exec()` | 扫描器 + 运行时（响应按纯文本解析） |
| C5 | 评判提示词对智能体输入做消毒 | `judgeguard`：消毒库 + 随机围栏提示词构建器 |
| C6 | 稳健的答案比较 | `exact_match` 检查器 |
| C7 | 验证逻辑真的在验证正确性 | 扫描器 |
| C8 | 不从智能体可写路径加载代码 | 检查器随评测器一起分发 |
| C9 | 每个任务独立环境快照 | `SecureRunner`：每任务独立临时目录 |
| C10 | 智能体与评测器日志分离、只追加 | `SecureRunner`：`logs/agent.log`、`logs/eval.log` |

## 项目结构

```
benchshield/
├── benchshield/
│   ├── scanner.py       # 七类漏洞的静态分析
│   ├── checklist.py     # Agent-Eval Checklist（C1-C10）评分
│   ├── sandbox.py       # VulnerableRunner / SecureRunner
│   ├── dockersandbox.py # 最强一档：每任务一个锁定容器（Docker 可选）
│   ├── redteam.py       # 零能力攻击载荷 + 诚实基线智能体
│   ├── netguard.py      # C2 防御：运行时强制网络阻断（socket/DNS 补丁）
│   ├── judgeguard.py    # V4 防御：评判提示词消毒 + 注入检测
│   ├── llmjudge.py      # LLM 评判：注入筛查 + fail-closed 的 PASS/FAIL 判定
│   ├── adapters.py      # SWE-bench / Terminal-Bench 接入（金标对智能体不可见）
│   ├── yamlmini.py      # 零依赖 YAML 子集解析器（配置 / compose 文件）
│   ├── benchdata.py     # 确定性的 5 类 mini 基准
│   ├── example_bench.py # 自包含的易攻破靶场生成器（demo 扫描目标）
│   ├── eval_worker.py   # 评测器入口（独立进程）
│   ├── report.py        # Markdown 报告渲染
│   └── __main__.py      # CLI：scan / demo / export-bench
├── examples/vulnerable_bench/   # 包含全部七类漏洞的演示基准
├── tests/                       # 108 项单元测试（标准库 unittest）
└── pyproject.toml
```

## 防御，而不只是检测

清单中的各项都自带可用的防御实现：

**`netguard` —— 运行时网络隔离（C2）。** 智能体执行期间，所有 Python 层网络 API
（`socket`、DNS 解析、`urllib`）都会抛出 `NetworkBlockedError`，尝试本身会记为篡改
事件。`SecureRunner` 默认开启，可用 `block_network=False` 显式关闭。

**`dockersandbox` —— 内核级任务隔离（C2/C9，最强一档）。** 每个任务的评测器都在一个
全新的、用完即弃的容器里执行：`--network none`（完全没有网络命名空间）、`--read-only`
根文件系统、`--tmpfs /workspace` 临时空间随容器一起消失、`--cap-drop ALL`、不使用
`--privileged`。代码与载荷全部经 **stdin** 传入——宿主文件系统一个都不挂载，V1 的
共享卷反模式在结构上就不可能发生。Docker 是可选的：守护进程不可用时运行器会**大声降级**
（结果显式标注为「仅进程隔离」），测试套件自动跳过。

```python
from benchshield.dockersandbox import DockerRunner

with DockerRunner(tasks, workspace_root="run1") as runner:
    report = runner.run(my_agent)  # 评测器在沙箱内执行
```

**`judgeguard` —— 评判提示词加固（V4）。** `sanitize()` 去除控制字符和伪造围栏并
限长；`detect_injection()` 标记常见提示词注入尝试（无视指令、角色劫持、强制输出、
泄露金标、聊天模板逃逸）；`build_judge_prompt()` 用**随机生成的围栏**包裹智能体
响应（无法预算），并附反注入前言。

```python
from benchshield.judgeguard import build_judge_prompt

prompt, report = build_judge_prompt(agent_response, gold)
if report.suspicious:
    ...  # 记录这次注入尝试
```

**`llmjudge` —— 安全地做语义评分（V4 防御的实际应用）。** `SemanticJudge` 可包裹
任意 `complete(prompt) -> str` 可调用对象（内置 `OllamaJudge`，兼容任意
OpenAI 风格 chat 端点，包括本地 Ollama，零依赖）。原始响应在**调用模型之前**就会被
筛查——被判定为注入的响应直接判该任务失败，永远不会送到裁判面前。判定必须是严格的
`PASS`/`FAIL`；其它任何情况（包括模型不可达）都算评判错误，任务**不会**被记为通过。
fail-closed，绝不 fail-open。

```python
from benchshield.llmjudge import SemanticJudge, OllamaJudge

judge = SemanticJudge(OllamaJudge(model="qwen3.5:9b"))
verdict = judge.judge(task_id, agent_response, gold)
```

**`adapters` —— 真实基准数据进得来，同样的保证出得去。** SWE-bench JSONL 文件与
Terminal-Bench 任务目录可载入内部任务模型，其中 `patch` / `test_patch` / `solution.sh`
被识别为金标答案（V2）：交给智能体的公开视图永远不含这些内容。扫描器也能识别
SWE-bench 的字段特征，所以一旦有 `instances.jsonl` 被丢进智能体工作区，就会像其它
金标泄露一样被标记。

```python
from benchshield.adapters import load_swebench, load_terminalbench

tasks = load_swebench("instances.jsonl")          # patch -> 金标
tasks = load_terminalbench("path/to/tasks")       # solution.sh -> 金标
```

**`yamlmini` —— YAML 子集解析器。** 无需 PyYAML 即可扫描基准配置和
docker-compose 文件。解析器刻意保守：支持配置常用子集（块映射、序列、标量），
对无法忠实表示的语法（锚点、流式集合、块字面量）**直接抛错**——错误解析隔离
配置比不解析更糟。compose 文件有专属 V1 规则：智能体服务用 `network_mode: host`、
智能体与评测器服务共享卷，均会被标记。

## 设计说明

- **易攻破的运行器本身就是一个功能。** `VulnerableRunner` 刻意复现了漏洞前提条件，让攻击载荷（以及你的防御）能够端到端地测试。
- **demo 就是把论文跑在本地。** `demo` 命令复现了 Berkeley RDI 的头条结论——零能力拿到 100%——随后用安全运行器把完全相同的攻击挡下来。
- **零依赖**，所以工具可以在任何地方运行，包括 CI 和离线机器。
- **扫描器自身也做纵深防御。** 脏配置（JSON 解析失败、顶层不是对象、字段类型错误）一律作为 finding 报出而不是静默跳过——审计工具绝不能在没读到的文件上宣称"干净"。

## 限制

- `netguard` 的网络阻断工作在 Python API 层；直接调用系统 socket 的原生扩展可绕过。
  需要内核级隔离时请使用内置的 `DockerRunner`（`--network none`），或在其上叠加
  namespace 隔离（Linux `unshare -n`）。
- Docker 这一档需要 Docker 守护进程（Linux 容器）；没有时 `DockerRunner` 会退回进程
  隔离，并把每条结果显式标注出来——它绝不会在没提供容器隔离时假装提供了。
- LLM 评判消毒（`judgeguard`、`llmjudge`）能减少并检测注入，但任何文本层防御都无法被
  *证明*对所有提示词攻击安全；语义评判器在边界答案上也可能出错——因此判定会记录错误
  与注入标记以便审计，而不是默认判通过。

## 路线图

- [x] YAML / docker-compose 配置扫描（`yamlmini` + compose 规则）
- [x] 运行时强制网络隔离（`netguard`，C2）
- [x] 评判提示词消毒库（`judgeguard`，V4）
- [x] 基于 Docker 的任务沙箱（`dockersandbox`，每任务全新容器）
- [x] SWE-bench / Terminal-Bench 任务格式适配器（`adapters`）
- [x] 基于 `judgeguard` 的语义（LLM）评判器集成（`llmjudge`）

## 参与贡献

欢迎提 Issue 和 PR。测试套件就是标准 `unittest`，零依赖：

```bash
python -m unittest discover -s tests -t .
```

## 参考资料

- UC Berkeley RDI，《Trustworthy Benchmarks》（2026）：零能力智能体攻破八大主流基准拿到接近满分；七类模式与清单的来源。
- Terminal-Bench 2.0：以「每个任务一个 Docker 容器」作为方法论标准。
- SWE-bench-Live：经过验证、无污染的排行榜实践。

## 许可证

MIT —— 见 [LICENSE](LICENSE)。
