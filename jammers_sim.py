#!/usr/bin/env python3
"""
jammers_sim.py — 无线电干扰源环境模拟器 (本地离线忠实复现)

对 Windows 客户端 "Jammers-simulator-full.exe" (Wails3/Go1.27) 仿真核心的
逐算法复现，用于本机练习、写策略、调优，最后再转回原格式。

被复现的函数 (二进制地址 → 本文件实现):
  counterSource.next / uintN / shuffle    0x1404f0020 / 0x1404f02a0 / 0x1404f0380
  scenario.GeneratePractice              0x1404eeda0
  scenario.insideJammerDisk              0x1404f19c0   (X^2 + Y^2 <= R^2)
  simcore.bearingnoise_ErrorDegrees      0x1404ee680   (BLAKE2b-8 平滑网格)
  simcore.QuantizeBearingHundredths      0x1404ee900   (round-half-away + 正模)
  simcore.normalizeDegrees               0x1404f5960   (fmod → 负修正 → -0 归零)
  simcore.directionalCoverage            0x1404f57e0   (半波束宽 90°, math.Remainder)
  simcore.measure                        0x1404f3940
  simcore.clear                          0x1404f4a00   (20m 清除 + cleared 位图)
  simcore.moveTo                         0x1404f5580   (移动 + 计时)
  simcore.Apply                          0x1404f2d60   (enter/measure/clear/exit 分派)

单位约定 (关键):
  * 机器人坐标 robotX/robotY : 米 (float64)
  * 干扰机坐标 jammer.X/Y     : 微单位 (int64), 除以 1e6 得米
  * receive / near / R        : 同为 int64 微单位, 除以 1e6 得米
  * direction (方向)          : int64 微度 (0..359999999), 除以 1e6 得度
  * 虚拟时钟 engine[0xb0]     : int64 微秒, 除以 1e6 得秒

接口语义 (对照附件2, 4 条指令):  /enter /measure /clear /exit
  移动/切频道没有独立指令, 由 /measure、/clear 的 position/channel 参数推断。
"""

from __future__ import annotations

import hashlib
import hmac
import math
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# --------------------------------------------------------------------------- #
# 常量 (均从 .text 段立即数/浮点常量解析得到)
# --------------------------------------------------------------------------- #
MICRO = 1_000_000.0

ARENA_R_MICRO = 1_770_000_000          # 0x69800e80  干扰机撒点圆盘半径 = 1770 m
NEAR_RADIUS_MICRO = 5_000_000          # engine[0x18] "near" 判定半径 = 5 m
CLEAR_RADIUS_MICRO = 20_000_000        # engine[0x20] 光学清除半径 = 20 m
RECEIVE_MIN_MICRO = 1_000_000_000      # 接收半径下限 = 1000 m
RECEIVE_SPAN_MICRO = 500_000_000       # 接收半径区间宽度 → [1000, 1500] m
DIRECTION_SPAN_MICRO = 360_000_000     # 0x15752a00  方向取值范围 [0, 360°) 微度
DIRECTION_HALF_BEAM_DEG = 90.0         # 0x40568000000112e1 ≈ 90.0 (定向两侧各 90°)

NOISE_GRID_M = 150.0                   # 0x4062c00000000000  噪声网格间距 (米)
NOISE_AMPLITUDE_DEG = 1.0              # 噪声 ∈ [-1, 1) 度, 量化时再钳位 ±1°

BEARING_SCALE = 100.0                  # 0x4059000000000000  量化到 1/100 度
BEARING_MOD = 36000                    # 0x8ca0  整圆 = 36000 个百分之一度

# —— 计时 / 运动常量 (附件2 + engine 字段) ——
MOVE_SPEED_M_S = 5.0                   # 移动速度 5 m/s (engine[0x28])
MOVE_SPEED_MICRO_PER_S = 5_000_000     # 同上, 微米/秒
SWITCH_S = 1.0                         # 切频道 1s (engine[0x30])
MEASURE_S = 5.0                        # 检测 5s   (engine[0x38])
CLEAR_SUCCESS_S = 5.0                  # 清除成功 5s (engine[0x40]: 精定位3s+清除2s)
CLEAR_NO_TARGET_S = 3.0                # 清除未发现 3s (engine[0x48]: 仅精定位3s)
COORD_LIMIT_M = 2_000_000.0            # 坐标分量上限 |x|,|y| ≤ 2e6 m (附件2)
VIRTUAL_TIME_LIMIT_S = 360_000.0       # 虚拟世界上限 100 小时
REAL_TIME_LIMIT_S = 1200.0             # /enter 后最长 20 分钟现实时间 (可配)

_2PI = 2.0 * math.pi                   # 0x401921fb54442d18
_2POW53 = 2.0 ** -53                   # 0x3ca0000000000000  (>>11 后恢复 53bit 均匀)


# --------------------------------------------------------------------------- #
# Go math.Round 的复现: round half AWAY from zero
# (Python 内建 round() 是"银行家舍入", 不可用!)
# --------------------------------------------------------------------------- #
def round_half_away(v: float) -> int:
    """等价于 Go math.Round(v) 后 cvttsd2si (截断转 int64)。"""
    return math.floor(v + 0.5) if v >= 0.0 else math.ceil(v - 0.5)


# --------------------------------------------------------------------------- #
# counterSource —— HMAC-SHA256 计数器 PRNG (0x1404f0020 等)
#   key    : 32 字节随机种子
#   msg    : "practice-case-v1" + name + "\x00" + uint32(counter) 大端
#   next   : 取 HMAC 摘要前 8 字节作 uint64
#   uintN  : 拒绝采样 (threshold = 2^64 % n)
#   shuffle: Fisher-Yates
# --------------------------------------------------------------------------- #
class CounterSource:
    def __init__(self, seed: bytes):
        if len(seed) != 32:
            raise ValueError("seed 必须是 32 字节")
        self.key = seed
        self.counters: Dict[str, int] = {}

    def next(self, name: str) -> int:
        n = self.counters.get(name, 0)
        msg = b"practice-case-v1" + name.encode() + b"\x00" + n.to_bytes(8, "big")
        h = hmac.new(self.key, msg, hashlib.sha256).digest()
        self.counters[name] = n + 1
        return int.from_bytes(h[:8], "big")

    def uintN(self, name: str, n: int) -> int:
        assert 0 < n <= (1 << 63), "n 必须 ∈ (0, 2^63]"
        # Go 的 -n % n 在 uint64 下 = 2^64 % n ; Python 里直接用 2^64 % n
        threshold = (1 << 64) % n
        while True:
            x = self.next(name)
            if x >= threshold:
                return x % n

    def shuffle(self, name: str, a: List[int]) -> List[int]:
        for i in range(len(a) - 1, 0, -1):
            j = self.uintN(name, i + 1)
            a[i], a[j] = a[j], a[i]
        return a


# --------------------------------------------------------------------------- #
# 噪声模型 (0x1404ee680 bearingnoise_ErrorDegrees / 0x1404eeac0 grid)
#   grid  : BLAKE2b(digest=8) of "%d:%d:%d:%d" % (salt, bl, col, row)
#           值域 [-1, 1)
#   error : 网格间距 150m, smoothstep 双线性插值, 幅值 ±1°
# --------------------------------------------------------------------------- #
def _noise_grid(salt: int, bl: int, col: int, row: int) -> float:
    h = hashlib.blake2b(
        f"{salt}:{bl}:{col}:{row}".encode(), digest_size=8
    )
    u = int.from_bytes(h.digest(), "big")
    return u / 2.0 ** 63 - 1.0


def bearing_noise_error_degrees(salt: int, bl: int, x_m: float, y_m: float) -> float:
    gx = x_m / NOISE_GRID_M
    gy = y_m / NOISE_GRID_M
    col = int(math.floor(gx))
    row = int(math.floor(gy))
    fx = gx - col
    fy = gy - row
    # 浮点边界保护 (gx-col 理论上 ∈ [0,1), 但舍入可能冒出 1.0)
    fx = 0.0 if fx < 0.0 else (1.0 if fx > 1.0 else fx)
    fy = 0.0 if fy < 0.0 else (1.0 if fy > 1.0 else fy)
    sx = fx * fx * (3.0 - 2.0 * fx)  # smoothstep
    sy = fy * fy * (3.0 - 2.0 * fy)
    v00 = _noise_grid(salt, bl, col, row)
    v10 = _noise_grid(salt, bl, col + 1, row)
    v01 = _noise_grid(salt, bl, col, row + 1)
    v11 = _noise_grid(salt, bl, col + 1, row + 1)
    top = v00 + (v10 - v00) * sx
    bot = v01 + (v11 - v01) * sx
    return top + (bot - top) * sy


# --------------------------------------------------------------------------- #
# 角度归一化与量化
# --------------------------------------------------------------------------- #
def normalize_degrees(deg: float) -> float:
    """0x1404f5960: fmod(deg,360) → 负修正 → -0.0 归零。"""
    d = math.fmod(deg, 360.0)
    if d < 0.0:
        d += 360.0
    if d == 0.0:
        d = 0.0  # 消除 -0.0
    return d


def quantize_bearing(true_deg: float, noise_deg: float) -> int:
    """0x1404ee900: 加噪 → round-half-away → 钳位 ±1° → 正模 36000。"""
    v = (true_deg + noise_deg) * BEARING_SCALE
    rounded = round_half_away(v)
    low = math.ceil((true_deg - 1.0) * BEARING_SCALE)
    high = math.floor((true_deg + 1.0) * BEARING_SCALE)
    v = int(max(low, min(high, rounded)))
    rem = v % BEARING_MOD
    if rem < 0:
        rem += BEARING_MOD  # 正模 (汇编 cmovl rax,rcx)
    return rem


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #
@dataclass
class Jammer:
    channel: int                 # 信道 id (1..20)
    x_micro: int                 # X 微单位 (int64)
    y_micro: int                 # Y 微单位 (int64)
    receive_micro: int           # 接收半径 微单位
    direction_type: str          # "omni" | "directional"
    direction_micro: Optional[int] = None  # 方向 微度 (directional 时非空)

    @property
    def x_m(self) -> float:
        return self.x_micro / MICRO

    @property
    def y_m(self) -> float:
        return self.y_micro / MICRO

    @property
    def receive_m(self) -> float:
        return self.receive_micro / MICRO

    @property
    def direction_deg(self) -> float:
        return (self.direction_micro or 0) / MICRO


@dataclass
class Scenario:
    seed_hex: str                # 32 字节种子 (hex), 用于复现同一局
    noise_seed: int              # uint64 噪声盐 (来自 next("noise-seed"))
    jammers: List[Jammer]        # 生成出的干扰机列表
    problem: int = 3             # 3=全向, 4=含定向

    @property
    def channels(self) -> List[int]:
        return [j.channel for j in self.jammers]

    def jammer_by_channel(self, channel: int) -> Optional[Jammer]:
        for j in self.jammers:
            if j.channel == channel:
                return j
        return None


# --------------------------------------------------------------------------- #
# GeneratePractice (0x1404eeda0)
# --------------------------------------------------------------------------- #
def generate_practice(seed: bytes, problem: int = 3) -> Scenario:
    """
    seed : 32 字节。problem: 3 (全向) 或 4 (含定向)。
    干扰机数量 10..16, 半径平方均匀分布, 角度均匀, 圆心盘内 (X^2+Y^2<=R^2)。

    注: 撒点半径 R = 1770m (二进制 0x69800e80), 小于题目"目标区域"半径 1800m;
        1800m 只是名义上的目标区域, 机器狗可提交区域外位置 (附件2), 不强制。
    """
    if len(seed) != 32:
        raise ValueError("seed 必须是 32 字节")
    if problem not in (3, 4):
        raise ValueError("problem 只能是 3 或 4")

    cs = CounterSource(seed)

    count = cs.uintN("count", 7)              # 0..6
    n_ch = count + 10                          # 10..16

    channels = list(range(1, 21))              # 1..20
    cs.shuffle("channels", channels)
    channels = channels[:n_ch]

    directional: Set[int] = set()
    if problem == 4:
        dcount = cs.uintN("directional-count", n_ch)   # 0..n_ch-1
        order = channels[:]
        cs.shuffle("directional-channels", order)
        directional = set(order[:dcount])

    jammers: List[Jammer] = []
    for ch in channels:
        # 圆心盘内均匀撒点: 半径平方均匀 (sqrt 恢复), 角度均匀, 圆角到微单位整数
        while True:
            rr = cs.next(f"jammer/{ch}/radius")
            r = math.sqrt((rr >> 11) * _2POW53) * ARENA_R_MICRO
            tr = cs.next(f"jammer/{ch}/theta")
            theta = (tr >> 11) * _2POW53 * _2PI
            X = round_half_away(r * math.cos(theta))
            Y = round_half_away(r * math.sin(theta))
            if X * X + Y * Y <= ARENA_R_MICRO * ARENA_R_MICRO:  # insideJammerDisk
                break

        receive = cs.uintN(f"jammer/{ch}/receive", RECEIVE_SPAN_MICRO + 1) + RECEIVE_MIN_MICRO
        is_dir = ch in directional
        direction = cs.uintN(f"jammer/{ch}/direction", DIRECTION_SPAN_MICRO) if is_dir else None

        jammers.append(Jammer(
            channel=ch,
            x_micro=X,
            y_micro=Y,
            receive_micro=receive,
            direction_type="directional" if is_dir else "omni",
            direction_micro=direction,
        ))

    noise_seed = cs.next("noise-seed")

    return Scenario(
        seed_hex=seed.hex(),
        noise_seed=noise_seed,
        jammers=jammers,
        problem=problem,
    )


# --------------------------------------------------------------------------- #
# directionalCoverage (0x1404f57e0)
# --------------------------------------------------------------------------- #
def directional_coverage(jammer: Jammer, robot_x_m: float, robot_y_m: float,
                         dist_m: float) -> bool:
    """
    机器人是否落在该干扰机的波束内。
    * 全向 → 恒真; 距离为 0 → 恒真。
    * 定向: bearing = normalize(atan2(robotY-Y, robotX-X)) (从干扰机指向机器人),
      与方向角求差后取 |math.Remainder(Δ, 360)| <= 90°。

    关键: 原码用 math.Remainder (0x1400e12e0, 返回 [-180,180] 内最短角差),
    而非 math.Mod (0x1400e0b80)。故波束关于方向角**对称** ±90°, 与题目
    "定向方向两侧各 90°(含)"、附件2 "有效覆盖角度范围 180°(含边界)" 一致。
    汇编里 `btr rax,0x3f` 清符号位即 abs(), 再与 90.0 比较。
    """
    if jammer.direction_type == "omni":
        return True
    if dist_m == 0.0:
        return True
    dy = robot_y_m - jammer.y_m
    dx = robot_x_m - jammer.x_m
    bearing = normalize_degrees(math.atan2(dy, dx) * 180.0 / math.pi)
    dir_deg = jammer.direction_deg
    diff = math.remainder(bearing - dir_deg, 360.0)  # Go math.Remainder
    return abs(diff) <= DIRECTION_HALF_BEAM_DEG


# --------------------------------------------------------------------------- #
# measure (0x1404f3940) —— 纯测量, 无状态 (供三角定位等算法直接调用)
# --------------------------------------------------------------------------- #
#: 返回类型: int = 量化方位角 (1/100 度, [0,36000)); 或以下字符串
MEASURE_NO_SIGNAL = "no_signal"
MEASURE_NEAR = "near"


def measure(scenario: Scenario, channel: int, robot_x_m: float, robot_y_m: float):
    """
    在 (robot_x_m, robot_y_m) 处对指定信道测向 (无 cleared 状态)。
    返回:
      * "near"      : 已进入 5m 近距 (定位成功)
      * int         : 量化方位角 (1/100 度)
      * "no_signal" : 无信号 (该信道无干扰机 / 超接收半径 / 定向未覆盖)
    判定顺序 (同原码): 接收半径 → 定向覆盖 → near → direction。
    """
    jammer = scenario.jammer_by_channel(channel)
    if jammer is None:
        return MEASURE_NO_SIGNAL

    dx = jammer.x_m - robot_x_m
    dy = jammer.y_m - robot_y_m
    dist = math.hypot(dx, dy)

    if dist > jammer.receive_m:
        return MEASURE_NO_SIGNAL
    if not directional_coverage(jammer, robot_x_m, robot_y_m, dist):
        return MEASURE_NO_SIGNAL
    if dist <= NEAR_RADIUS_MICRO / MICRO:
        return MEASURE_NEAR

    # 真方位角: 从机器人指向干扰机 (atan2(Y/1e6-robotY, X/1e6-robotX))
    true_deg = normalize_degrees(math.atan2(dy, dx) * 180.0 / math.pi)
    noise = bearing_noise_error_degrees(scenario.noise_seed, channel, robot_x_m, robot_y_m)
    return quantize_bearing(true_deg, noise)


# --------------------------------------------------------------------------- #
# 异常
# --------------------------------------------------------------------------- #
class SimulationError(Exception):
    """模拟器运行期错误 (未进入、已退出等)。"""


class VirtualTimeout(SimulationError):
    """虚拟世界 100 小时超时 (engine[0x50] 限制)。"""


# --------------------------------------------------------------------------- #
# Simulator —— 带完整状态与虚拟时钟的命令级仿真
#   对应 engine 字段:  position(0x98/0xa0) / channel(0xa8) / cleared(0xac 位图)
#                     virtual_time(0xb0) / entered(0x90) / exited(0x91)
# --------------------------------------------------------------------------- #
class Simulator:
    def __init__(self, scenario: Scenario, robot_id: str = "0",
                 real_time_limit_s: float = REAL_TIME_LIMIT_S):
        self.scenario = scenario
        self.robot_id = robot_id
        self.real_time_limit_s = real_time_limit_s
        # 状态
        self.entered = False
        self.exited = False
        self.position: Tuple[float, float] = (0.0, 0.0)  # 米, 初始 (0,0)
        self.channel = 1                                 # 测向机当前频道, 初始 1
        self.cleared: Set[int] = set()                   # 已清除信道
        self.virtual_time_us = 0                         # 虚拟时间 (微秒)
        self.virtual_time_limit_us = int(VIRTUAL_TIME_LIMIT_S * 1e6)

    # ------------------------------------------------------------------ #
    # 内部: 虚拟时钟推进与运动
    # ------------------------------------------------------------------ #
    @property
    def virtual_time_s(self) -> float:
        return self.virtual_time_us / 1e6

    def _advance(self, us: int) -> None:
        self.virtual_time_us += us
        if self.virtual_time_us >= self.virtual_time_limit_us:
            self.exited = True
            raise VirtualTimeout(
                f"虚拟世界超时 ({self.virtual_time_s:.3f}s >= {VIRTUAL_TIME_LIMIT_S}s)"
            )

    def _move_to(self, x: float, y: float) -> None:
        """移动到 (x,y), 按直线距离/速度推进虚拟时钟 (复现 moveTo 0x1404f5580)。"""
        dx = x - self.position[0]
        dy = y - self.position[1]
        dist = math.hypot(dx, dy)
        # 复现 Go: duration = (dist * 1e12) / 5e6 ; cvttsd2si 截断 → 微秒
        dur_us = int((dist * 1e12) / MOVE_SPEED_MICRO_PER_S)
        self._advance(dur_us)
        self.position = (x, y)

    @staticmethod
    def _validate_channel(channel: int) -> None:
        if not isinstance(channel, int) or isinstance(channel, bool):
            raise ValueError(f"channel 必须是 1..20 的整数, 得到 {channel!r}")
        if not (1 <= channel <= 20):
            raise ValueError(f"channel 必须在 1..20, 得到 {channel}")

    @staticmethod
    def _validate_coord(x: float, y: float) -> None:
        if abs(x) > COORD_LIMIT_M or abs(y) > COORD_LIMIT_M:
            raise ValueError(
                f"坐标分量须满足 |x|,|y| ≤ {COORD_LIMIT_M:g} m, 得到 ({x}, {y})"
            )

    def _require_entered(self) -> None:
        if not self.entered:
            raise SimulationError("尚未成功调用 /enter (not_entered)")
        if self.exited:
            raise SimulationError("测试已结束 (test_ended)")

    # ------------------------------------------------------------------ #
    # /enter
    # ------------------------------------------------------------------ #
    def enter(self) -> Dict:
        """进入目标区域。不推进虚拟时钟。返回 remaining_real_duration_s。"""
        if self.exited:
            raise SimulationError("测试已结束, 不能再次 /enter")
        if self.entered:
            raise SimulationError("已进入 (already_entered)")
        self.entered = True
        return {
            "accepted": True,
            "virtual_time_s": self.virtual_time_s,
            "remaining_real_duration_s": int(self.real_time_limit_s),
        }

    # ------------------------------------------------------------------ #
    # /measure
    # ------------------------------------------------------------------ #
    def measure(self, channel: int, x: float, y: float) -> Dict:
        """
        移动到 (x,y) 并对 channel 检测。总耗时 = 移动 + 切频道(若变) + 检测(5s)。
        返回 API 风格: {accepted, virtual_time_s, measure_result, svd_deg}
          measure_result ∈ {"no_signal","near","direction"}
          svd_deg: direction 时返回, 保留两位小数 (示向度, 含误差)
        """
        self._require_entered()
        self._validate_channel(channel)
        self._validate_coord(x, y)

        self._move_to(x, y)                       # 移动 (可能 0)
        if channel != self.channel:               # 切频道
            self._advance(int(SWITCH_S * 1e6))
            self.channel = channel
        self._advance(int(MEASURE_S * 1e6))       # 检测

        # 检测结果 (含 cleared 位图判断)
        if channel in self.cleared:
            return {
                "accepted": True,
                "virtual_time_s": self.virtual_time_s,
                "measure_result": MEASURE_NO_SIGNAL,
                "svd_deg": None,
            }
        res = measure(self.scenario, channel, x, y)
        if res == MEASURE_NEAR:
            return {
                "accepted": True,
                "virtual_time_s": self.virtual_time_s,
                "measure_result": MEASURE_NEAR,
                "svd_deg": None,
            }
        if res == MEASURE_NO_SIGNAL:
            return {
                "accepted": True,
                "virtual_time_s": self.virtual_time_s,
                "measure_result": MEASURE_NO_SIGNAL,
                "svd_deg": None,
            }
        return {
            "accepted": True,
            "virtual_time_s": self.virtual_time_s,
            "measure_result": "direction",
            "svd_deg": res / 100.0,               # 保留两位小数
        }

    # ------------------------------------------------------------------ #
    # /clear
    # ------------------------------------------------------------------ #
    def clear(self, channel: int, x: float, y: float) -> Dict:
        """
        移动到 (x,y) 并清除 channel 的干扰机。总耗时 = 移动 + 清除(3s 未发现 / 5s 成功)。
        channel 不切换测向机当前频道、不产生切频道耗时。
        返回 {accepted, virtual_time_s, clear_result}
          clear_result ∈ {"success","no_target_in_range"}
        清除半径 20m, 与定向朝向无关; 已清除/不存在/超 20m 均视为未发现。
        """
        self._require_entered()
        self._validate_channel(channel)
        self._validate_coord(x, y)

        self._move_to(x, y)                       # 移动 (可能 0), 不切频道

        jammer = self.scenario.jammer_by_channel(channel)
        dist = math.hypot(jammer.x_m - x, jammer.y_m - y) if jammer is not None else math.inf

        # 判定: 不存在 / 已清除 / 超 20m → 未发现 (3s)
        if jammer is None or channel in self.cleared or dist > CLEAR_RADIUS_MICRO / MICRO:
            self._advance(int(CLEAR_NO_TARGET_S * 1e6))
            return {
                "accepted": True,
                "virtual_time_s": self.virtual_time_s,
                "clear_result": "no_target_in_range",
            }

        # 成功清除 (5s)
        self.cleared.add(channel)
        self._advance(int(CLEAR_SUCCESS_S * 1e6))
        return {
            "accepted": True,
            "virtual_time_s": self.virtual_time_s,
            "clear_result": "success",
        }

    # ------------------------------------------------------------------ #
    # /exit
    # ------------------------------------------------------------------ #
    def exit(self, reason: str = "user_exit") -> Dict:
        """结束测试。不推进虚拟时钟。"""
        if not self.entered:
            raise SimulationError("尚未 /enter (not_entered)")
        self.exited = True
        return {
            "accepted": True,
            "virtual_time_s": self.virtual_time_s,
            "exit_reason": reason,
        }

    # ------------------------------------------------------------------ #
    # 便捷查询 (供策略)
    # ------------------------------------------------------------------ #
    @property
    def uncleared_channels(self) -> List[int]:
        """尚未清除的信道列表 (策略仍需探测/清除的目标)。"""
        return [j.channel for j in self.scenario.jammers if j.channel not in self.cleared]

    @property
    def all_cleared(self) -> bool:
        return len(self.cleared) >= len(self.scenario.jammers)

    def snapshot(self) -> Dict:
        return {
            "entered": self.entered,
            "exited": self.exited,
            "position": self.position,
            "channel": self.channel,
            "cleared": sorted(self.cleared),
            "virtual_time_s": self.virtual_time_s,
            "uncleared": self.uncleared_channels,
        }


# --------------------------------------------------------------------------- #
# 演示 / 自测
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import secrets

    seed = secrets.token_bytes(32)
    scen = generate_practice(seed, problem=4)

    print(f"seed      = {scen.seed_hex}")
    print(f"noise_seed= {scen.noise_seed:#018x}")
    print(f"problem   = {scen.problem}")
    print(f"干扰机数量 = {len(scen.jammers)}")
    print()
    print(f"{'信道':>4} {'X(m)':>9} {'Y(m)':>9} {'接收(m)':>7} {'类型':>12} {'方向(°)':>8}")
    for j in scen.jammers:
        d = j.direction_deg if j.direction_micro is not None else float("nan")
        print(f"{j.channel:>4} {j.x_m:>9.1f} {j.y_m:>9.1f} {j.receive_m:>7.1f} "
              f"{j.direction_type:>12} {d:>8.2f}")

    # 完整命令流演示
    sim = Simulator(scen)
    print("\n=== 命令流演示 ===")
    print("enter:", sim.enter())
    # 在原点附近测一下频道 1 (假设频道 1 存在)
    ch = scen.channels[0]
    r = sim.measure(ch, 0.0, 0.0)
    print(f"measure(ch={ch}, 0,0):", r)
    # 找到某个干扰机, 直接去它位置清除
    j = scen.jammers[0]
    r = sim.clear(j.channel, j.x_m, j.y_m)
    print(f"clear(ch={j.channel}, at jammer):", r)
    # 再测已被清除的频道 → no_signal
    r = sim.measure(j.channel, j.x_m, j.y_m)
    print(f"measure(cleared ch={j.channel}):", r)
    print("exit:", sim.exit())
    print("\n最终状态:", sim.snapshot())
