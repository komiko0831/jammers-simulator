# jammers_sim — 无线电干扰源环境模拟器（本地离线版）

对高教社杯 2026 数学建模竞赛 B 题《无线电干扰源的快速自动定位与清除》提供的
Windows 客户端 `Jammers-simulator-full.exe`（Wails v3 + Go 1.27）仿真核心，做的一份
**自包含、离线可跑、算法逐条对齐**的 Python 复现。

用途：在本地复现练习局 → 用 Python 写策略、调优 → 优化到满意后，再把策略转回
原接口格式（附件 2 的 JSON 协议）提交。

> **安全边界**：本仓库只做**练习模式**的本地模拟与策略优化。对正式 ground-truth
> 包的解密/逆向属于破坏竞赛核心挑战的作弊行为，明确不做、也不提供任何相关代码。

---

## 文件结构

```
jammers_sim.py    # 唯一产物：完整模拟器（PRNG / 撒点 / 噪声 / 测向 / 清除 / 时钟）
README.md         # 本文档
```

无需第三方依赖，仅用 Python 3.8+ 标准库（`hashlib` `hmac` `math` `secrets` 等）。

---

## 快速开始

```python
import secrets
import jammers_sim as S

# 1. 复现一局练习赛（seed 是 32 字节随机数，用同一 seed 可精确复现同一局）
scen = S.generate_practice(secrets.token_bytes(32), problem=4)  # 4 = 含定向干扰机

# 2. 建一个带状态、带虚拟时钟的命令级仿真器
sim = S.Simulator(scen)

# 3. 按真实接口的四条指令驱动
sim.enter()                    # 进入，不推进虚拟时钟
sim.measure(channel, x, y)     # 移动到 (x,y) 并对该频道测向
sim.clear(channel, x, y)       # 移动到 (x,y) 并清除该频道干扰机
sim.exit()                     # 退出

# 4. 查看状态
print(sim.snapshot())          # position / channel / cleared / virtual_time_s ...
```

`problem` 取值：`3` 为全向干扰机，`4` 为含定向干扰机（与题目 B 题一致）。

---

## 四条指令与返回格式

所有方法的返回 dict 与真实 API 的 JSON **同构**，策略代码可无缝对接真实接口。

### `/enter`
进入目标区域。机器人初始位置 `(0,0)`，测向机初始频道 `1`。**不推进虚拟时钟**。

```python
{"accepted": True, "virtual_time_s": 0.0, "remaining_real_duration_s": 1200}
```

`remaining_real_duration_s` 是现实时间预算（默认 20 分钟，可在 `Simulator(...)` 里配）。

### `/measure(channel, x, y)`
移动到 `(x,y)` 并对 `channel` 测向。**总耗时 = 移动 + 切频道（若变）+ 检测 5s**。
检测结束后，测向机当前频道更新为该 `channel`。

```python
{"accepted": True, "virtual_time_s": 6.0,
 "measure_result": "direction" | "near" | "no_signal",
 "svd_deg": 64.99}          # 仅 direction 时返回，示向度（含误差），保留两位小数
```

三种 `measure_result`：

| 结果 | 含义 |
| --- | --- |
| `no_signal` | 该频道无未清除干扰源 / 超出接收距离 / 不在定向覆盖内 / 已清除 |
| `near` | 距干扰机 ≤ 5 m 且在其覆盖内（即定位成功） |
| `direction` | 返回量化示向度 `svd_deg`（1/100 度，含 ±1° 噪声） |

### `/clear(channel, x, y)`
移动到 `(x,y)` 并清除该频道干扰机。**总耗时 = 移动 + 清除（3s 或 5s）**。
`/clear` **不切频道**、不产生切频道耗时、不改变测向机当前频道。

```python
{"accepted": True, "virtual_time_s": 223.77, "clear_result": "success" | "no_target_in_range"}
```

| 结果 | 含义 | 耗时 |
| --- | --- | --- |
| `success` | 距干扰机 ≤ 20 m（与定向朝向无关） | 5s（精定位 3s + 清除 2s） |
| `no_target_in_range` | 该频道不存在干扰机 / 已清除 / 距离 > 20 m | 3s |

一个干扰机只能被清除一次，第二次清除返回 `no_target_in_range`；清除后该频道 `measure`
恒返回 `no_signal`。

### `/exit`
结束测试。**不推进虚拟时钟**。

```python
{"accepted": True, "virtual_time_s": 228.77, "exit_reason": "user_exit"}
```

---

## 计时模型（虚拟时钟）

| 动作 | 耗时 | 说明 |
| --- | --- | --- |
| 移动 | `dist / 5 (m/s)` | 按直线距离，`trunc(dist*1e12/5e6)` 微秒 |
| 切频道 | 1 s | 仅 `/measure` 且 `channel != 当前频道` 时 |
| 检测 | 5 s | `/measure` 固定，无论结果 |
| 清除成功 | 5 s | `/clear` |
| 清除未发现 | 3 s | `/clear` |
| enter / exit | 0 s | 不推进时钟 |

约束（与真实接口一致）：

- 坐标分量 `|x|, |y| ≤ 2 000 000 m`（越界抛 `ValueError`）
- `channel ∈ [1, 20]`（越界抛 `ValueError`）
- 虚拟世界上限 `360 000 s`（100 小时），超时抛 `VirtualTimeout`
- 未 `enter` 就 `measure/clear` 抛 `SimulationError`

---

## 关键算法事实（对照二进制逐条确认）

这些是非显然、容易抄错的细节，已按反汇编原样复现：

- **单位**：机器人坐标是**米**（float64）；干扰机的 X/Y、接收半径、near、R 是**微单位**
  （int64，除以 `1e6` 得米）；方向是**微度**（`0..359999999`）；虚拟时间是**微秒**。
- **PRNG** `counterSource`：HMAC-SHA256，key 为 32 字节 seed，msg 为
  `"practice-case-v1" + name + "\x00" + uint32(counter)`（大端），取摘要前 8 字节；
  `uintN` 用 `2^64 % n` 阈值拒绝采样；Fisher–Yates 洗牌。
- **撒点** `GeneratePractice`：干扰机数量 10..16；圆心盘内均匀（半径**平方**均匀 + 角度均匀），
  `X²+Y² ≤ R²` 判定；撒点半径 `R = 1770 m`（题面"目标区域"1800 m 是名义值，不强制）。
- **接收半径**：`1000 m + uintN(500_000_000)`，即 `[1000, 1500] m`。
- **噪声模型**：`BLAKE2b(digest=8)` of `"%d:%d:%d:%d" % (salt, 频道, col, row)`，网格间距
  150 m，smoothstep 双线性插值，幅值 `±1°`。
- **示向度量化**：加噪 → **round half away from zero**（不是 Python 内建 `round`）→
  钳位到真方位 ±1° → 正模 `36000`。
- **角度归一化**：`math.fmod(deg, 360)`（不是 `%`）→ 负则 `+360` → `-0.0` 归 `+0.0`。
- **定向覆盖**：`bearing = atan2(robotY-Y, robotX-X)`（从干扰机指向机器人），
  `|math.remainder(bearing - dir, 360)| ≤ 90°`。**对称 ±90°**；全向恒真；距离为 0 恒真。
- **测向判定顺序**：接收半径 → 定向覆盖 → near(≤5m) → direction。
- **清除位图** `engine[0xac]`：`measure` 只读不写，`clear` 成功才置位。

---

## 写策略的两种方式

1. **命令级（推荐）**：直接驱动 `Simulator`，返回格式与真实 API 一致，写完即可转格式提交。
2. **算法级**：调用无状态纯函数 `S.measure(scen, ch, x, y)`，返回 `near` / `no_signal` /
   量化方位角 `int`，用于三角定位、逼近等纯计算调优，不牵涉时钟与状态。

辅助查询：

```python
sim.uncleared_channels   # 尚未清除的信道列表
sim.all_cleared          # 是否已全部清除
sim.virtual_time_s       # 当前虚拟时间（秒）
scen.jammer_by_channel(c)  # 取某信道干扰机（策略调试用，含真实坐标）
```

> 调试时 `scen.jammers` 里有干扰机的**真实坐标/方向/接收半径**（等于逆向得到的
> ground-truth 撒点），可用于检验策略的定位误差；正式提交时这些字段不可见。

---

## 交叉验证

`counterSource` PRNG 与撒点已用一份独立的 Go 实现对拍，**20/20 种子完全一致**；噪声、
量化、定向覆盖、清除判定均已对照二进制反汇编逐指令确认。自测脚本见
`jammers_sim.py` 末尾 `__main__` 块：

```bash
python3 jammers_sim.py
```
