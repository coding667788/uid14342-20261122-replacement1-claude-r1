# mirror_plan

`mirror_plan` 是一个纯本地、仅依赖 Python 3.12 标准库与 SQLite 的命令行工具，
用于在隔离实验网中安排**可审计的链路镜像采样**。所有输入都是自定义合成 JSON，
所有计算只使用 CPU，输出只包含授权证据与覆盖证据，不含任何流量本体。

- 精确求解动作子集（分支定界，非启发式）
- 五元组精确授权、grant 修订链与 revoke 裁剪
- 端口组物理约束、跨场景故障的采集器覆盖证明
- 确定性规范化摘要（sha256），不信任计划自报证据
- SQLite 事务入库、乐观并发（expected-head）、request-id 幂等重放

## 1. 命令一览

所有命令都把**恰好一个 UTF-8 JSON 文档**写到 stdout。

| 命令 | 作用 |
| --- | --- |
| `python -m mirror_plan plan CASE.json` | 求最优计划；合法输入不可行时输出 `infeasible` 与极小冲突集 |
| `python -m mirror_plan audit CASE.json PLAN.json` | 完全重算授权/端口/覆盖/摘要并复核 |
| `python -m mirror_plan record CASE.json PLAN.json --db audit.sqlite --request-id ID --expected-head N` | 事务内复核并持久化 |
| `python -m mirror_plan history --db audit.sqlite --commit N` | 读取某提交冻结的回执与证据 |

退出码：

- `0`：成功，或合法输入得到 `infeasible` 结论
- `2`：结构/字段错误（stdout 带稳定 `field` 路径）
- `3`：审计不通过、提交冲突、历史版本不存在

## 2. 输入字段（CASE.json）

| 字段 | 说明 |
| --- | --- |
| `as_of` | 策略视图冻结点；只看 `seq <= as_of` 的事件 |
| `taps[]` | `id, switch, port_group`；同 `port_group` 同时段只能运行一个动作 |
| `policy[]` | 有序事件，`seq` 从 1 连续递增 |
| `candidates[]` | 采样动作，见下 |
| `requirements[]` | 覆盖要求 |
| `scenarios[]` | 至少一个 `id="base"` 且故障列表为空的场景 |

**grant 事件**：`seq, event="grant", key, revision, tap, collector, tenant,
class, label, from, to`。每个 key 的首个 revision 为 1，之后每次 +1；
后一个 grant **整段取代**前一修订的作用域与时间窗。

**revoke 事件**：`seq, event="revoke", key, revision, effective_at`，必须准确
指向该 key 当前最新且未撤销的 grant。撤销后该修订只能覆盖 `effective_at` 之前
的部分（区间左闭右开，边界立即恢复）。

**采样动作**：`id, tap, collector, start, end, cost, visibility[]`。
- 时间都是 `[0, 10^9]` 内整数，区间左闭右开、起点小于终点
- `cost` 为非负整数；未选动作成本为零，已选动作即使在故障场景失效也计原成本
- `visibility[]` 每项为 `tenant, class, label, from, to`，区间必须落在动作内，
  每个动作至少一条
- 授权要求与 `(tap, collector, tenant, class, label)` 五元组**精确相等**，
  不跨租户/采集器/镜像点继承

**覆盖要求**：`id, tenant, class, from, to, min_collectors`，
`min_collectors ∈ [1,3]`。每个原子片内必须有至少该数量的**不同采集器**
收到相符 tenant/class 的授权样本；同一采集器多条相符清单只算一次。
只有动作、visibility、采集器、交换设备都覆盖该片时才计数。

**场景故障**：`switch_failures[]` 与 `collector_failures[]`，每项
`device, from, to`。不同场景共用同一组动作，故障只影响覆盖；所有动作在
base 场景必须满足隐私（授权）与端口约束。

ID 规则：1–64 字符的 ASCII `[A-Za-z0-9_.-]+`，同一 JSON 内除修订链外不重复。

规模上限：26 动作、8 场景、40 要求、200 策略事件、160 visibility 项。

## 3. 输出字段与失败排序

### plan（可行）

```json
{
  "status": "feasible",
  "cost": 13,
  "selected_ids": ["a1", "a2"],
  "plan_digest": "sha256:ab12...",
  "authorization_evidence": [ /* 每个选中动作的逐片授权证据 */ ],
  "coverage_evidence": [ /* 按 scenario_id、requirement_id 排序 */ ]
}
```

- **目标排序**：先比成本和，再比动作数，再比已排序动作 ID 列表的 ASCII 字节序。
- **授权证据**：visibility 按授权边界切成原子片，逐片选 `(key, revision)`
  字节序最小的见证，再合并相邻且同见证的片段；`holes` 给出未授权子段。
- **覆盖证据**：每个原子片选按 ID 排序的前 `min_collectors` 个有效采集器，
  每个采集器取字节序最小的动作作见证，合并相邻相同见证。

### plan（不可行）

`status="infeasible"`，附带 `minimal_conflict`：
- 规则：按要求 ID **从大到小**依次尝试删除；只有剩余要求仍不可行时才永久删除。
- `deleted_requirement_ids`：被永久删除的要求
- `retained_witnesses`：对每个保留要求，给出“删除它之后”的可行见证
  （同一最优排序）；删到零条要求时见证为空计划。

### audit 失败优先级（从高到低）

1. **结构**：未知动作 ID 等，带字段路径
2. **授权**：按
   `(action_id, tenant, class, label, visibility_from, visibility_to, hole_start, hole_end)`
   取首项
3. **端口**：按
   `(tap_group, overlap_start, overlap_end, action_id_1, action_id_2)` 取首个
4. **覆盖**：按 `(scenario_id, requirement_id, start, end)` 取首个原子片，
   并附 `actual_collectors`
5. **摘要**：重算摘要与 `plan_digest` 不一致

证据与摘要全部由工具重算，不信任 PLAN.json 的自报结果。

### 摘要规范化

- 形式：`sha256:` + 小写十六进制
- 哈希对象：`{"case": <规范化案例>, "selected_ids": <已排序动作 ID>}`
- 规范化 JSON：`ensure_ascii=False, sort_keys=True, separators=(",", ":")`，
  UTF-8 编码
- 无顺序语义的列表按对象 `id`（无 id 时按全部字段元组）排序；`policy` 保持
  `seq` 顺序
- 因此文件空白、字段顺序、候选顺序都不影响摘要

## 4. 入库语义（record / history）

提交号从 **0** 起单调递增，每个成功提交 +1。

`record` 在单个事务内按以下顺序处理：

1. **先做 request-id 幂等判定（优先于 expected-head）**
   - 同 request-id 且重算摘要相同 → 返回原提交号与同一回执（`replayed`），
     即使 expected-head 错误也如此（用于响应丢失后的重放）
   - 同 request-id 但摘要不同 → 冲突（退出码 3）
2. 其他 request-id：只有 `expected-head` 等于库当前提交号**且复核成功**才能提交
3. 复核以工具重算摘要为准；PLAN.json 的 `plan_digest` 必须与重算值一致
4. 任何异常都回滚，事务内无部分写入；新提交号只增加一次

一次成功提交持久化：规范化案例、动作、摘要、授权与覆盖见证、提交号。
关闭进程后重开数据库，`history` 返回完全相同的冻结视图；不存在的 `N`
返回退出码 3 与明确错误。

## 5. 精确求解采用的裁剪与索引

候选最多 26 个，子集空间 2^26，工具用分支定界精确求解（见
`mirror_plan/solver.py`）：

1. **授权前置裁剪**：每个动作只算一次授权，unsafe 动作在搜索前剔除
   （含 unsafe 动作的计划不可能有效）。
2. **覆盖索引**：`CoverageIndex` 为每个“场景 × 要求”的原子片预计算
   “动作 → 采集器”的贡献表，可行性检查退化为集合查找而非区间重扫。
3. **覆盖剪枝**：若“当前选择 + 所有未决定动作”都无法满足某片，立即剪枝。
4. **端口剪枝**：动作仅在不与已选动作于同端口组时间重叠时才进入包含分支。
5. **支配剪枝**：当前目标（成本、数量、ID 序列）已不可能优于现任最优解时剪枝。
6. **状态记忆**：记忆已访问的 `(位置, 选择掩码)`，消除重复分支。

## 6. 复跑办法

一键端到端演示（生成规模用例、规划、审计、不可行冲突、入库与历史）：

```bash
bash examples/run_examples.sh
```

单独复跑规模用例（26 动作 / 6 场景 / 24 要求，跨 revoke 与故障边界）：

```bash
python examples/generate_scale_case.py examples/output/scale_case.json
python -m mirror_plan plan examples/output/scale_case.json
```

手写小样例：

- `examples/small_case.json`：可行，含 revoke、故障切换与多采集器见证
- `examples/infeasible_case.json`：不可行，演示极小冲突集

运行自动化测试（含两个进程竞争同一提交头、同 request-id 并发重放、
提交前故障、提交后响应丢失的子进程夹具）：

```bash
python -m unittest discover -s tests -v
```

## 7. 包结构

```
mirror_plan/
  validation.py   结构校验与稳定字段路径
  policy.py       as_of 策略视图、原子切片、授权证据
  coverage.py     端口约束、场景覆盖索引与见证合并
  solver.py       分支定界精确求解与极小冲突集
  digest.py       规范化 JSON 与 sha256 摘要
  planner.py      plan 组装与重算式 audit
  store.py        SQLite 事务、幂等与乐观并发
  cli.py          命令行入口与退出码
examples/         手写用例、规模用例生成器、一键脚本
tests/            unittest 自动化测试与子进程并发夹具
```
