#!/usr/bin/env bash
# =============================================================================
# ipraw_lab.sh —— 实验一 5.3.5「原始套接字」一键验证脚本
#
# 用法（不需要改任何路径，脚本自己定位仓库）：
#     bash ipraw_lab.sh
#
# 脚本做的事：
#   1. 自动找到本仓库根目录，检查 cmake / g++ / tcpdump，并申请一次 sudo 授权
#   2. 编译 apps/ip_raw.cc → build/apps/ip_raw
#   3. 权限对照：故意不带 sudo 跑一次，留下 EPERM 实证（报告第 6 条要用）
#   4. 用 Linux 网络命名空间造一台独立对端主机 10.9.9.2（自带独立协议栈），
#      与本机 10.9.9.1 用一对 veth 虚拟网线直连
#   5. 双端同时 tcpdump，发送 3 个协议号 253 的数据报
#   6. 自动比对「程序打印的首部字节」与「对端抓到的首部字节」是否逐字节一致，
#      并按 IP 首部偏移逐字段核对版本/总长/TTL/协议号/地址
#   7. 输出报告截图所需文件路径，并清理临时网络环境
#
# 说明：仓库位于 /mnt/hgfs 共享目录且原地编译失败时，脚本自动复制到家目录重试。
# =============================================================================

set -uo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; CYN=$'\033[36m'; RST=$'\033[0m'
step() { printf "\n${CYN}==== %s ====${RST}\n" "$*"; }
ok()   { printf "${GRN}[OK]${RST} %s\n" "$*"; }
warn() { printf "${YEL}[!]${RST} %s\n" "$*"; }
die()  { printf "${RED}[x]${RST} %s\n" "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
  warn "当前是以 root 运行的。建议改用普通用户执行： bash ipraw_lab.sh"
  warn "（脚本内部会按需单独 sudo；整体 root 运行会让 build/ 产物属主变成 root）"
fi

# ---- 实验参数（全部写死，无需修改）------------------------------------------
NS_NAME="ipraw_peer"        # 对端主机的网络命名空间名
VETH_LOCAL="ipraw0"         # 留在本机的一端
VETH_PEER="ipraw1"          # 放进对端的一端
LOCAL_IP="10.9.9.1"         # 本机地址
PEER_IP="10.9.9.2"          # 对端地址
PREFIX_LEN="24"
PROTO="253"                 # 自定义协议号（RFC 3692 实验用途）
TTL="64"
PAYLOAD="32"                # 载荷字节数
COUNT="3"                   # 发送个数
OUT_DIR="$HOME/ipraw_result"

SEND_LOG="$OUT_DIR/send.log"
SENDER_PCAP="$OUT_DIR/sender.pcap"
PEER_PCAP="$OUT_DIR/peer.pcap"
PERM_LOG="$OUT_DIR/permission_denied.log"

# 无论脚本如何退出，都清理临时网络环境（-n 避免在超时后卡住等密码）
cleanup() {
  sudo -n ip netns del "$NS_NAME" 2>/dev/null || true
  sudo -n ip link del "$VETH_LOCAL" 2>/dev/null || true
}
trap cleanup EXIT

# ---- 阶段 0：定位仓库 -------------------------------------------------------
step "阶段 0/5  定位仓库"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$SCRIPT_DIR"
[ -f "$REPO/apps/ip_raw.cc" ] || REPO="$(cd "$SCRIPT_DIR/.." && pwd)"
[ -f "$REPO/apps/ip_raw.cc" ] || die "找不到 apps/ip_raw.cc。请把本脚本放在仓库根目录（与 CMakeLists.txt 同级）再执行。"
ok "仓库根目录: $REPO"
ok "待编译源码: $REPO/apps/ip_raw.cc（$(wc -l < "$REPO/apps/ip_raw.cc") 行）"

# ---- 阶段 1：检查依赖 -------------------------------------------------------
step "阶段 1/5  检查依赖"

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "缺少命令 $1，请先按指导书代码 4-1 安装工具链"; }
need_cmd cmake
need_cmd g++
need_cmd tcpdump
need_cmd ip
ok "cmake   $(cmake --version | head -1 | awk '{print $3}')"
ok "g++     $(g++ -dumpversion 2>/dev/null || g++ --version | head -1 | awk '{print $NF}')"
ok "tcpdump $(tcpdump --version 2>/dev/null | head -1 | awk '{print $3}')"

if ! sudo -n true 2>/dev/null; then
  printf "${YEL}创建网络命名空间、抓包与原始套接字都需要管理员权限，请输入密码：${RST}\n"
  sudo -v || die "获取 sudo 权限失败"
fi
ok "已获得 sudo 授权"

mkdir -p "$OUT_DIR"
# 若此前以 root 跑过，把目录交还当前用户，避免 tee 写不进旧文件
sudo -n chown -R "$(id -u):$(id -g)" "$OUT_DIR" 2>/dev/null || true
ok "产物目录: $OUT_DIR"

# ---- 阶段 2：编译 -----------------------------------------------------------
step "阶段 2/5  编译 ip_raw"

build_in() {
  local dir="$1"
  ( cd "$dir" && cmake -S . -B build 2>&1 && cmake --build build --target ip_raw -j"$(nproc)" 2>&1 )
}

BUILD_LOG=$(build_in "$REPO")
BUILD_RC=$?

# 共享目录（vmhgfs）偶发不支持某些文件属性，失败则自动复制到家目录重试
if [ "$BUILD_RC" -ne 0 ] && [[ "$REPO" == /mnt/hgfs/* ]]; then
  warn "共享目录内编译失败，自动复制到家目录重试..."
  WORK="$HOME/ipraw_src"
  # 只删除本脚本自己创建的工作副本，避免误删用户数据
  if [ -f "$WORK/CMakeLists.txt" ]; then rm -rf "$WORK"; fi
  mkdir -p "$WORK"
  for item in CMakeLists.txt apps src util etc tests scripts; do
    if [ -e "$REPO/$item" ]; then cp -a "$REPO/$item" "$WORK/"; fi
  done
  REPO="$WORK"
  ok "工作副本: $REPO"
  BUILD_LOG=$(build_in "$REPO")
  BUILD_RC=$?
fi

if [ "$BUILD_RC" -ne 0 ]; then
  printf "%s\n" "$BUILD_LOG" | tail -30
  die "编译失败，以上为最后 30 行输出"
fi
ok "编译成功"

APP="$REPO/build/apps/ip_raw"
[ -x "$APP" ] || die "未生成可执行文件: $APP"
ok "可执行文件: $APP"

# ---- 阶段 2.5：权限对照（报告第 6 条的实证）---------------------------------
step "阶段 2.5  权限对照：不加 sudo 应被拒绝"

# 注意这里显式用 -s 指定源地址：此时 10.9.9.2 还没建，自动探测会先失败，
# 加上 -s 才能直接走到 socket() 看到真正的 EPERM。
PERM_OUT=$("$APP" "$PEER_IP" -s "$LOCAL_IP" -n 1 2>&1 || true)
printf "%s\n" "$PERM_OUT" > "$PERM_LOG"
if printf "%s" "$PERM_OUT" | grep -q "管理员权限"; then
  ok "普通用户执行被拒绝 —— 这正是 CAP_NET_RAW 缺失的表现"
  printf "  %s\n" "$(printf "%s" "$PERM_OUT" | head -1)"
else
  warn "未复现权限拒绝（当前用户可能已带 CAP_NET_RAW），已记录输出到 $PERM_LOG"
fi

# ---- 阶段 3：搭建独立对端主机 -----------------------------------------------
step "阶段 3/5  搭建独立对端主机（网络命名空间 $NS_NAME）"

sudo -n ip netns del "$NS_NAME" 2>/dev/null || true
sudo -n ip link del "$VETH_LOCAL" 2>/dev/null || true

sudo -n ip netns add "$NS_NAME" || die "创建网络命名空间失败"
sudo -n ip link add "$VETH_LOCAL" type veth peer name "$VETH_PEER" || die "创建 veth 失败"
sudo -n ip link set "$VETH_PEER" netns "$NS_NAME"

sudo -n ip addr add "$LOCAL_IP/$PREFIX_LEN" dev "$VETH_LOCAL"
sudo -n ip link set "$VETH_LOCAL" up
sudo -n ip netns exec "$NS_NAME" ip addr add "$PEER_IP/$PREFIX_LEN" dev "$VETH_PEER"
sudo -n ip netns exec "$NS_NAME" ip link set "$VETH_PEER" up
sudo -n ip netns exec "$NS_NAME" ip link set lo up

if sudo -n ip netns exec "$NS_NAME" ping -c 1 -W 1 "$LOCAL_IP" >/dev/null 2>&1; then
  ok "本机 $LOCAL_IP ($VETH_LOCAL)  <== veth 直连 ==>  对端 $PEER_IP ($VETH_PEER @ ns:$NS_NAME)"
else
  warn "对端 ping 不通，但原始套接字发送不依赖 ICMP，继续执行"
fi

# ---- 阶段 4：双端抓包并发送 -------------------------------------------------
step "阶段 4/5  双端抓包并发送 $COUNT 个报文"

sudo -n tcpdump -n -i "$VETH_LOCAL" -w "$SENDER_PCAP" "ip proto $PROTO" >/dev/null 2>&1 &
PID_SENDER=$!
sudo -n ip netns exec "$NS_NAME" tcpdump -n -i "$VETH_PEER" -w "$PEER_PCAP" "ip proto $PROTO" >/dev/null 2>&1 &
PID_PEER=$!
sleep 1

sudo -n "$APP" "$PEER_IP" -n "$COUNT" -l "$PAYLOAD" -t "$TTL" -p "$PROTO" 2>&1 | tee "$SEND_LOG"
SEND_RC=${PIPESTATUS[0]}

sleep 1
# 停抓包：先按 PID，再用 pkill 兜底（sudo 的 PID 未必等于 tcpdump 的 PID）
sudo -n kill "$PID_SENDER" "$PID_PEER" 2>/dev/null || true
sudo -n pkill -f "tcpdump.*$VETH_LOCAL" 2>/dev/null || true
sudo -n pkill -f "tcpdump.*$VETH_PEER" 2>/dev/null || true
# 等 tcpdump 真正退出，否则 pcap 尾部未写完读出来会截断
for _ in 1 2 3 4 5 6; do
  pgrep -f "tcpdump.*$VETH_LOCAL" >/dev/null 2>&1 || pgrep -f "tcpdump.*$VETH_PEER" >/dev/null 2>&1 || break
  sleep 0.3
done

[ "$SEND_RC" -eq 0 ] || warn "发送环节返回码 $SEND_RC，请查看上方日志"

# ---- 阶段 5：对端验证与自动比对 ---------------------------------------------
step "阶段 5/5  对端抓包结果"

[ -s "$PEER_PCAP" ] || die "对端未抓到任何报文，请查看上方的抓包与发送输出"
[ -s "$SENDER_PCAP" ] || warn "发送侧未抓到报文（不影响对端结论）"

PEER_LINES=$(sudo -n tcpdump -n -r "$PEER_PCAP" 2>/dev/null | grep -c "ip-proto-$PROTO" || true)
[ -n "$PEER_LINES" ] || PEER_LINES=0
printf "对端收到 %s 个 ip-proto-%s 报文（期望 %s 个）\n\n" "$PEER_LINES" "$PROTO" "$COUNT"
sudo -n tcpdump -n -r "$PEER_PCAP" 2>/dev/null | head -10

printf "\n---- 对端抓到的字节（-x，含以太网头 14 字节）----\n"
sudo -n tcpdump -n -r "$PEER_PCAP" -x -c 1 2>/dev/null | head -4

# 提取两侧首部字节做逐字节比对
PROG_HEX=$(grep -m1 '首部字节:' "$SEND_LOG" 2>/dev/null | sed 's/.*首部字节:[[:space:]]*//' | tr -d '[:space:]' || true)
CAP_RAW=$(sudo -n tcpdump -n -r "$PEER_PCAP" -x -c 1 2>/dev/null \
          | grep -E '0x00(00|10|20):' | sed 's/.*0x00[0-9a-f]*:[[:space:]]*//' | tr -d '[:space:]' || true)
# 跳过以太网头 14 字节（28 个十六进制字符），取 IP 首部 20 字节（40 个字符）
CAP_HEX="${CAP_RAW:28:40}"

printf "\n---- 首部字节自动比对 ----\n"
printf "  程序打印: %s\n" "${PROG_HEX:-（未提取到）}"
printf "  对端抓包: %s\n" "${CAP_HEX:-（未提取到）}"

if [ -n "$PROG_HEX" ] && [ "$PROG_HEX" = "$CAP_HEX" ]; then
  ok "逐字节一致 —— 手工构造的 IP 首部原样到达对端"
elif [ -n "$CAP_HEX" ]; then
  warn "未自动匹配（可能因链路层封装差异），请肉眼对照上面两组十六进制"
else
  warn "未能提取对端首部，请直接看上面的 -x 输出"
fi

# 按 IP 首部偏移逐字段核对
printf "\n---- 关键字段核对（按偏移取值）----\n"
if [ -n "$CAP_HEX" ] && [ "${#CAP_HEX}" -ge 40 ]; then
  TOT_BYTES=$(( 20 + PAYLOAD ))
  TOT_HEX=$(printf "%04x" "$TOT_BYTES")
  TTL_HEX=$(printf "%02x" "$TTL")

  if [ "${CAP_HEX:0:2}" = "45" ]; then
    ok "偏移 0   版本/首部长度 = 0x45（IPv4，20 字节首部）"
  else
    warn "偏移 0   版本/首部长度 = 0x${CAP_HEX:0:2}（期望 0x45）"
  fi
  if [ "${CAP_HEX:4:4}" = "$TOT_HEX" ]; then
    ok "偏移 2   总长度 = 0x$TOT_HEX（$TOT_BYTES 字节 = 20 首部 + $PAYLOAD 载荷）"
  else
    warn "偏移 2   总长度 = 0x${CAP_HEX:4:4}（期望 0x$TOT_HEX）"
  fi
  if [ "${CAP_HEX:16:2}" = "$TTL_HEX" ]; then
    ok "偏移 8   TTL = 0x$TTL_HEX（$TTL）"
  else
    warn "偏移 8   TTL = 0x${CAP_HEX:16:2}（期望 0x$TTL_HEX）"
  fi
  if [ "${CAP_HEX:18:2}" = "fd" ]; then
    ok "偏移 9   协议号 = 0xfd（253），不是 TCP(6) 或 UDP(17)"
  else
    warn "偏移 9   协议号 = 0x${CAP_HEX:18:2}（期望 0xfd）"
  fi
  printf "  偏移 12  源地址字节 = %s（应为本机 %s）\n" "${CAP_HEX:24:8}" "$LOCAL_IP"
  printf "  偏移 16  目的地址字节 = %s（应为对端 %s）\n" "${CAP_HEX:32:8}" "$PEER_IP"
else
  warn "首部字节不足 20 字节，跳过逐字段核对"
fi

# 对端回 ICMP protocol unreachable → 证明包真的进了对端协议栈
ICMP_HIT=$(sudo -n tcpdump -n -r "$SENDER_PCAP" 2>/dev/null | grep -c "protocol-unreachable" || true)
[ -n "$ICMP_HIT" ] || ICMP_HIT=0
if [ "$ICMP_HIT" -gt 0 ]; then
  ok "发送侧收到 $ICMP_HIT 条 ICMP protocol-unreachable —— 对端协议栈确实解析了该报文"
fi

# ---- 收尾 -------------------------------------------------------------------
step "清理与产物"
cleanup
trap - EXIT
ok "已清理网络命名空间与 veth"

printf "\n报告截图可用产物：\n"
printf "  发送端完整输出   %s\n" "$SEND_LOG"
printf "  权限拒绝证据     %s\n" "$PERM_LOG"
printf "  发送侧抓包       %s\n" "$SENDER_PCAP"
printf "  对端抓包         %s\n" "$PEER_PCAP"
printf "\n复查命令（随时可再跑，抓包文件已存盘，帧号不变）：\n"
printf "  sudo tcpdump -n -r %s\n" "$PEER_PCAP"
printf "  sudo tcpdump -n -r %s -X\n" "$PEER_PCAP"
printf "\n"
ok "5.3.5 验证流程结束"
