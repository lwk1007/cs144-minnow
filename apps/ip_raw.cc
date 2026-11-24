/**
 * ip_raw.cc -- 实验一 5.3.5：原始套接字手工构造 IPv4 首部并发送自定义协议号数据报
 *
 * 编译：cmake --build build --target ip_raw -j4
 * 运行：sudo ./build/apps/ip_raw <目标IP> [-n 次数] [-l 载荷字节] [-t TTL] [-p 协议号] [-s 源IP]
 * 示例：sudo ./build/apps/ip_raw 192.168.159.1 -n 3 -l 32 -t 64 -p 253
 *
 * 四个设计要点（对应报告 6.5 节的原理分析）：
 *   1. socket(AF_INET, SOCK_RAW, IPPROTO_RAW)：Linux 上该组合隐含开启 IP_HDRINCL，
 *      内核不再替报文生成 IP 首部，20 字节首部完全由本程序填写——这是"亲手构造"的前提。
 *   2. 协议号默认 253：RFC 3692 将 253/254 保留给"实验与测试"用途，不与 TCP(6)/UDP(17)
 *      等真实协议冲突，抓包时用 ip.proto == 253 一筛即得本程序的报文。
 *   3. 首部校验和按 RFC 1071 的 16 位反码和自行计算，不依赖内核补零机制，
 *      因此抓包中看到的校验和是程序算出的值，可与手算结果逐位对照。
 *   4. 源地址不硬编码：先用一个 UDP 套接字对目标做 connect（不发包，只查路由表），
 *      再从 getsockname 取本机出口地址，避免换网络环境后源码失效。
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std;

// ---- 本实验使用的常量 -------------------------------------------------------
// 协议号 253：RFC 3692 "Assigning Experimental and Testing Numbers" 划定的实验用途号，
// 不与任何注册协议冲突，抓包过滤器 ip.proto == 253 可精确定位本程序的报文。
constexpr uint8_t DEFAULT_PROTOCOL = 253;
constexpr uint8_t DEFAULT_TTL = 64;
constexpr int DEFAULT_COUNT = 3;
constexpr int DEFAULT_PAYLOAD = 32;

constexpr size_t IP_HEADER_LEN = 20;      // IPv4 首部无选项时固定 20 字节
constexpr int MAX_PAYLOAD = 1400;         // 小于 MTU 1500 - 20，避免触发 EMSGSIZE 分片
constexpr int MAX_COUNT = 100;

// ---- IPv4 首部结构（RFC 791）------------------------------------------------
// 用 pragma pack 关闭编译器填充，保证 sizeof 恰好 20 字节，与线上格式逐字节对应。
#pragma pack( push, 1 )
struct IpHeader
{
  uint8_t ver_ihl;    // [0] 版本(高 4 位) + 首部长度(低 4 位，单位为 4 字节)
  uint8_t tos;        // [1] 区分服务，本实验恒 0
  uint16_t tot_len;   // [2-3] 总长度 = 首部 + 载荷，网络字节序
  uint16_t id;        // [4-5] 标识，同一数据报的多个分片共享此值
  uint16_t frag_off;  // [6-7] 标志(高 3 位) + 片偏移(低 13 位)，本实验置 0
  uint8_t ttl;        // [8] 生存时间，每经一台路由器减 1，为 0 则丢弃
  uint8_t protocol;   // [9] 上层协议号
  uint16_t check;     // [10-11] 首部校验和，仅覆盖首部 20 字节
  uint32_t saddr;     // [12-15] 源地址
  uint32_t daddr;     // [16-19] 目的地址
};
#pragma pack( pop )

static_assert( sizeof( IpHeader ) == IP_HEADER_LEN, "IPv4 首部必须恰好 20 字节" );

// ---- 命令行选项 -------------------------------------------------------------
// 注意：每个成员都带 {} 或默认值（NSDMI）。框架启用了 -Weffc++ 与 -Werror，
// 该规则要求所有成员都必须显式初始化，否则编译直接失败：
//   error: 'Options::target' should be initialized in the member initialization list
struct Options
{
  string target {};                  // 目的 IP（必填）
  string source {};                  // 源 IP，空表示自动探测
  int count { DEFAULT_COUNT };       // 发送个数
  int payload_len { DEFAULT_PAYLOAD }; // 载荷字节数
  int ttl { DEFAULT_TTL };           // 生存时间
  int protocol { DEFAULT_PROTOCOL }; // 协议号
  int id { -1 };                     // 固定标识值，-1 表示按进程号自动生成
};

static void show_usage( const char* argv0 )
{
  cerr << "Usage: sudo " << argv0 << " <dst-ip> [options]\n\n"
       << "  -n <count>      发送报文个数，1.." << MAX_COUNT << "（默认 " << DEFAULT_COUNT << "）\n"
       << "  -l <bytes>      载荷字节数，0.." << MAX_PAYLOAD << "（默认 " << DEFAULT_PAYLOAD << "）\n"
       << "  -t <ttl>        生存时间，1..255（默认 " << static_cast<int>( DEFAULT_TTL ) << "）\n"
       << "  -p <proto>      协议号，0..255（默认 " << static_cast<int>( DEFAULT_PROTOCOL ) << "）\n"
       << "  -i <id>         固定 IP 标识值，0..65535（默认取进程号并逐个递增）\n"
       << "  -s <src-ip>     强制指定源地址（默认按路由自动探测）\n"
       << "  -h              显示本帮助\n\n"
       << "  例：sudo " << argv0 << " 192.168.159.1 -n 3 -p 253\n"
       << "  提示：对端用 Wireshark 过滤 ip.proto == " << static_cast<int>( DEFAULT_PROTOCOL )
       << " 即可看到本程序发出的报文。\n"
       << "  技巧：固定 -i 后分别用 -t 64 与 -t 63 各发一次，两次首部仅 TTL 不同，\n"
       << "        可实测校验和恰好相差 0x0100。\n";
}

// 把字符串转成整数，非法输入直接抛异常（比 atoi 静默返回 0 更容易定位误用）
static int parse_int( const string& text, const string& opt )
{
  size_t used = 0;
  int value = 0;
  try {
    value = stoi( text, &used );
  } catch ( const exception& ) {
    throw invalid_argument( "选项 " + opt + " 需要一个整数，收到 \"" + text + "\"" );
  }
  if ( used != text.size() ) {
    throw invalid_argument( "选项 " + opt + " 的取值 \"" + text + "\" 含非数字字符" );
  }
  return value;
}

static Options parse_args( int argc, char* argv[] )
{
  Options opts;
  for ( int i = 1; i < argc; ++i ) {
    const string arg { argv[i] };
    const bool has_next = ( i + 1 < argc );

    auto take_value = [&]( const string& name ) -> string {
      if ( !has_next ) {
        throw invalid_argument( "选项 " + name + " 缺少取值" );
      }
      return string { argv[++i] };
    };

    if ( arg == "-h" || arg == "--help" ) {
      show_usage( argv[0] );
      exit( EXIT_SUCCESS );
    } else if ( arg == "-n" ) {
      opts.count = parse_int( take_value( arg ), arg );
    } else if ( arg == "-l" ) {
      opts.payload_len = parse_int( take_value( arg ), arg );
    } else if ( arg == "-t" ) {
      opts.ttl = parse_int( take_value( arg ), arg );
    } else if ( arg == "-p" ) {
      opts.protocol = parse_int( take_value( arg ), arg );
    } else if ( arg == "-i" ) {
      opts.id = parse_int( take_value( arg ), arg );
    } else if ( arg == "-s" ) {
      opts.source = take_value( arg );
    } else if ( !arg.empty() && arg[0] == '-' ) {
      throw invalid_argument( "未知选项 " + arg );
    } else if ( opts.target.empty() ) {
      opts.target = arg;
    } else {
      throw invalid_argument( "只能指定一个目的地址，多余参数：" + arg );
    }
  }

  if ( opts.target.empty() ) {
    throw invalid_argument( "缺少目的地址" );
  }
  if ( opts.count < 1 || opts.count > MAX_COUNT ) {
    throw invalid_argument( "次数 -n 需在 1.." + to_string( MAX_COUNT ) + " 之间" );
  }
  if ( opts.payload_len < 0 || opts.payload_len > MAX_PAYLOAD ) {
    throw invalid_argument( "载荷长度 -l 需在 0.." + to_string( MAX_PAYLOAD ) + " 之间" );
  }
  if ( opts.ttl < 1 || opts.ttl > 255 ) {
    throw invalid_argument( "TTL -t 需在 1..255 之间" );
  }
  if ( opts.protocol < 0 || opts.protocol > 255 ) {
    throw invalid_argument( "协议号 -p 需在 0..255 之间" );
  }
  if ( opts.id > 65535 ) {
    throw invalid_argument( "标识 -i 需在 0..65535 之间" );
  }
  return opts;
}

// ---- 16 位反码和校验和（RFC 1071）-------------------------------------------
// 算法分四步：① 按 16 位大端切字累加；② 奇数长度末字节左移 8 位补零参与；
// ③ 进位回卷（高 16 位加到低 16 位，重复至不再溢出）；④ 按位取反。
// 只用首部 20 字节，不覆盖载荷——这是 IP 层"尽力而为"的一个侧面：
// 首部错了整包丢弃，载荷错了交给上层自己校验（TCP/UDP 各自有校验和）。
static uint16_t checksum16( const void* data, size_t len )
{
  const auto* bytes = static_cast<const uint8_t*>( data );
  uint32_t sum = 0;

  for ( size_t i = 0; i + 1 < len; i += 2 ) { // ① 两个字节合成一个 16 位大端字
    sum += ( static_cast<uint32_t>( bytes[i] ) << 8 ) | bytes[i + 1];
  }
  if ( ( len & 1U ) != 0U ) {                 // ② 奇数长度：末字节当高 8 位
    sum += static_cast<uint32_t>( bytes[len - 1] ) << 8;
  }
  while ( ( sum >> 16 ) != 0U ) {             // ③ 进位回卷
    sum = ( sum & 0xFFFFU ) + ( sum >> 16 );
  }
  return static_cast<uint16_t>( ~sum & 0xFFFFU ); // ④ 取反
}

// ---- 探测本机出口地址 --------------------------------------------------------
// 技巧：建一个 UDP 套接字并 connect 到目标。UDP connect 不发任何报文，
// 只是让内核查一次路由表并把"默认出口地址"绑定上去，随后 getsockname 即可读出。
// 这样换网络（NAT 网段变化、桥接、真机）都不用改源码，比硬编码 192.168.159.128 稳妥。
static in_addr probe_source_addr( const in_addr& dst )
{
  const int probe = socket( AF_INET, SOCK_DGRAM, 0 );
  if ( probe < 0 ) {
    throw runtime_error( string { "创建探测套接字失败: " } + strerror( errno ) );
  }

  sockaddr_in peer {};
  peer.sin_family = AF_INET;
  peer.sin_addr = dst;
  peer.sin_port = htons( 9 ); // discard 端口，仅为满足 connect 参数要求

  in_addr local_addr {};
  if ( connect( probe, reinterpret_cast<const sockaddr*>( &peer ), sizeof( peer ) ) == 0 ) {
    sockaddr_in local {};
    socklen_t len = sizeof( local );
    if ( getsockname( probe, reinterpret_cast<sockaddr*>( &local ), &len ) == 0 ) {
      local_addr = local.sin_addr;
    }
  }
  close( probe );

  if ( local_addr.s_addr == 0 ) {
    throw runtime_error( "无法探测本机出口地址，请用 -s 手工指定源 IP" );
  }
  return local_addr;
}

// ---- 输出辅助 ---------------------------------------------------------------
static string ip_to_string( const in_addr& addr )
{
  char buf[INET_ADDRSTRLEN] = {};
  if ( inet_ntop( AF_INET, &addr, buf, sizeof( buf ) ) == nullptr ) {
    return "?";
  }
  return buf;
}

static void dump_hex( const string& label, const uint8_t* data, size_t len )
{
  cout << label;
  for ( size_t i = 0; i < len; ++i ) {
    if ( i != 0 && i % 4 == 0 ) {
      cout << ' ';
    }
    cout << hex << setw( 2 ) << setfill( '0' ) << static_cast<int>( data[i] );
  }
  cout << dec << setfill( ' ' ) << '\n';
}

static void print_header( const IpHeader& ip, size_t payload_len )
{
  const int ver = ip.ver_ihl >> 4;
  const int ihl = ( ip.ver_ihl & 0x0FU ) * 4;
  const uint16_t tot = ntohs( ip.tot_len );
  const uint16_t id = ntohs( ip.id );
  const uint16_t frag = ntohs( ip.frag_off );

  cout << "  +----------------- IP 首部逐字段 ----------------+\n"
       << "  | 版本            " << ver << "  (IPv" << ver << ")\n"
       << "  | 首部长度        " << ihl << " 字节 (" << ( ip.ver_ihl & 0x0FU ) << " x 4)\n"
       << "  | 区分服务 TOS   0x" << hex << setw( 2 ) << setfill( '0' ) << static_cast<int>( ip.tos ) << dec
       << setfill( ' ' ) << "\n"
       << "  | 总长度          " << tot << " 字节 (首部 " << ihl << " + 载荷 " << payload_len << ")\n"
       << "  | 标识 ID        0x" << hex << setw( 4 ) << setfill( '0' ) << id << dec << setfill( ' ' ) << " (" << id << ")\n"
       << "  | 标志/片偏移    0x" << hex << setw( 4 ) << setfill( '0' ) << frag << dec << setfill( ' ' )
       << " (DF=" << ( ( frag & 0x4000U ) != 0U ? 1 : 0 ) << " MF=" << ( ( frag & 0x2000U ) != 0U ? 1 : 0 )
       << " 偏移=" << ( frag & 0x1FFFU ) << ")\n"
       << "  | 生存时间 TTL   " << static_cast<int>( ip.ttl ) << "\n"
       << "  | 协议号          " << static_cast<int>( ip.protocol ) << "\n"
       << "  | 首部校验和      0x" << hex << setw( 4 ) << setfill( '0' ) << ntohs( ip.check ) << dec << setfill( ' ' ) << "\n";

  in_addr s {};
  in_addr d {};
  s.s_addr = ip.saddr;
  d.s_addr = ip.daddr;
  cout << "  | 源地址          " << ip_to_string( s ) << "\n"
       << "  | 目的地址        " << ip_to_string( d ) << "\n"
       << "  +-----------------------------------------------+\n";
}

// ---- 主流程 -----------------------------------------------------------------
int main( int argc, char* argv[] )
{
  try {
    if ( argc <= 0 ) {
      abort(); // 与框架其它 app 保持一致：不允许 access argv[0] when argc <= 0
    }
    if ( argc == 1 ) {
      show_usage( argv[0] );
      return EXIT_FAILURE;
    }

    const Options opts = parse_args( argc, argv );

    // 1) 解析目的地址（同时充当格式校验，非法 IP 在这里就被拦下）
    sockaddr_in dst {};
    dst.sin_family = AF_INET;
    if ( inet_pton( AF_INET, opts.target.c_str(), &dst.sin_addr ) != 1 ) {
      throw invalid_argument( "目的地址不是合法的 IPv4 点分十进制串: " + opts.target );
    }

    // 2) 确定源地址
    in_addr src {};
    if ( !opts.source.empty() ) {
      if ( inet_pton( AF_INET, opts.source.c_str(), &src ) != 1 ) {
        throw invalid_argument( "源地址不是合法的 IPv4 点分十进制串: " + opts.source );
      }
    } else {
      src = probe_source_addr( dst.sin_addr );
    }

    // 3) 创建原始套接字。IPPROTO_RAW 在 Linux 上隐含 IP_HDRINCL：
    //    内核认为"首部已由用户提供"，只做转发，不再生成任何 IP 字段。
    //    普通用户执行会在此返回 EPERM，因为 SOCK_RAW 需要 CAP_NET_RAW 能力。
    const int fd = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
    if ( fd < 0 ) {
      if ( errno == EPERM ) {
        cerr << "socket(SOCK_RAW) 被拒绝: 需要管理员权限。请用 sudo 重新执行：\n"
             << "  sudo " << argv[0] << " " << opts.target << "\n";
      } else {
        cerr << "创建原始套接字失败: " << strerror( errno ) << "\n";
      }
      return EXIT_FAILURE;
    }

    // 显式置 IP_HDRINCL：对 IPPROTO_RAW 内核已默认开启，这里再设一次是为了让代码意图可见；
    // 万一某平台已默认且拒绝重复设置，按提示降级继续，不致命。
    const int one = 1;
    if ( setsockopt( fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof( one ) ) < 0 ) {
      cerr << "note: setsockopt(IP_HDRINCL) 返回 " << strerror( errno )
           << "（IPPROTO_RAW 已默认开启，继续执行）\n";
    }

    const size_t total_len = IP_HEADER_LEN + static_cast<size_t>( opts.payload_len );
    cout << "原始套接字已就绪: fd=" << fd << "  协议号=" << opts.protocol << "  TTL=" << opts.ttl << "\n"
         << "源 " << ip_to_string( src ) << " -> 目的 " << opts.target << "  共 " << opts.count << " 个报文，"
         << "每个 " << total_len << " 字节（首部 20 + 载荷 " << opts.payload_len << "）\n"
         << "提示: 发送期间在对端执行 tcpdump -n -i 任意接口 'ip proto " << opts.protocol
         << "'，或在 Wireshark 用过滤条件 ip.proto == " << opts.protocol << "\n\n";

    // 标识字段的起始值取进程号低 16 位，逐个递增，便于在对端抓包时区分本进程的报文
    const uint16_t base_id = static_cast<uint16_t>( getpid() & 0xFFFF );

    vector<uint8_t> packet( total_len, 0 );

    for ( int i = 0; i < opts.count; ++i ) {
      // 4) 逐字段填写 IP 首部（字段顺序与 RFC 791 一致，偏移见 struct 注释）。
      //    这里用对齐的局部对象，而不是把 vector 缓冲区强转成 IpHeader*：
      //    vector<uint8_t> 只保证 1 字节对齐，强转成含 uint16/uint32 成员的结构体，
      //    在 x86 上能跑（仅降速），在 ARM 等严格对齐平台上会直接触发异常。
      IpHeader ip {};

      // 标识：-i 指定时用固定值（便于跨运行只改 TTL 对比校验和），否则按进程号递增
      const uint16_t this_id = ( opts.id >= 0 ) ? static_cast<uint16_t>( opts.id )
                                                : static_cast<uint16_t>( base_id + i );

      ip.ver_ihl = 0x45; // 版本 4（高 4 位）+ 首部长度 5（低 4 位，5 x 4 = 20 字节）
      ip.tos = 0x00;     // 区分服务，本实验不使用 QoS
      ip.tot_len = htons( static_cast<uint16_t>( total_len ) ); // 含首部的总长度，网络序
      ip.id = htons( this_id );                                 // 标识，同一数据报的各分片共享
      ip.frag_off = htons( 0x0000 );                            // DF=0 MF=0 偏移=0，允许分片
      ip.ttl = static_cast<uint8_t>( opts.ttl );                // 生存时间由发送方设定
      ip.protocol = static_cast<uint8_t>( opts.protocol );      // 自定义协议号
      ip.check = 0;                                             // 先置 0 再计算，否则结果错
      ip.saddr = src.s_addr;
      ip.daddr = dst.sin_addr.s_addr;

      // 载荷：填一段可读文本，抓包时在十六进制区能直接认出本程序的报文；
      // 若载荷长于文本则余下保持 0，短于文本则截断。
      const string text = "CS144-Minnow ip_raw proto=" + to_string( opts.protocol ) + " seq="
                          + to_string( i + 1 ) + "/" + to_string( opts.count );
      const size_t copy_len = min( text.size(), static_cast<size_t>( opts.payload_len ) );
      if ( copy_len > 0 ) {
        memcpy( packet.data() + IP_HEADER_LEN, text.data(), copy_len );
      }

      // 5) 计算并回填首部校验和。此刻 ip.check 仍为 0，符合"计算前该字段须置零"的前提；
      //    算完再整块拷进报文缓冲，保证线上字节与打印内容完全一致。
      ip.check = htons( checksum16( &ip, IP_HEADER_LEN ) );
      memcpy( packet.data(), &ip, IP_HEADER_LEN );

      // 6) 发送。IPPROTO_RAW 下首部里的 daddr 才是权威，但 sockaddr 仍需填写，
      //    内核会用 sin_addr 做一次合法性检查（全 0 会被判 EINVAL）。
      const ssize_t sent = sendto( fd,
                                   packet.data(),
                                   packet.size(),
                                   0,
                                   reinterpret_cast<const sockaddr*>( &dst ),
                                   sizeof( dst ) );
      if ( sent < 0 ) {
        cerr << "第 " << ( i + 1 ) << " 个报文发送失败: " << strerror( errno ) << "\n";
        if ( errno == EMSGSIZE ) {
          cerr << "  提示: 载荷过大超过链路 MTU，请用 -l 减小长度\n";
        }
        close( fd );
        return EXIT_FAILURE;
      }

      cout << "========== 报文 " << ( i + 1 ) << "/" << opts.count << "  已发出 " << sent << " 字节 ==========\n";
      dump_hex( "  首部字节: ", packet.data(), IP_HEADER_LEN );
      cout << "  " << "载荷文本: ";
      for ( size_t k = 0; k < copy_len; ++k ) {
        cout << static_cast<char>( packet[IP_HEADER_LEN + k] );
      }
      cout << "\n";
      print_header( ip, static_cast<size_t>( opts.payload_len ) );
      cout << "\n";

      if ( i + 1 < opts.count ) {
        this_thread::sleep_for( chrono::seconds( 1 ) ); // 间隔 1 秒，便于抓包时看清逐个到达
      }
    }

    close( fd );

    cout << "全部 " << opts.count << " 个报文发送完毕。\n"
         << "核对要点：\n"
         << "  1. 对端报文首部 Protocol 应为 " << opts.protocol << "（不是 TCP 6 / UDP 17）；\n"
         << "  2. 对端看到的 TTL 与上面打印的一致（同一广播域内转发不减 TTL）；\n"
         << "  3. 十六进制首部的前 20 字节应与“首部字节”一行逐字节相同。\n";
  } catch ( const exception& e ) {
    cerr << "错误: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
