package recon

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// workerPoolSize 固定工作协程数量，绝不为每个 IP 创建协程，避免触发 Termux 的幽灵进程杀手。
	workerPoolSize = 256

	// jobQueueSize 任务队列容量，两倍工作协程即可填满流水线，同时避免占用过多移动端内存。
	jobQueueSize = workerPoolSize * 2

	// resultQueueSize 结果队列容量，防止工作协程因主协程短暂停顿而阻塞。
	resultQueueSize = workerPoolSize * 2

	// dialTimeout 连接超时，400ms 足以覆盖局域网往返，又能快速越过 DROP 型防火墙。
	dialTimeout = 400 * time.Millisecond

	// bannerReadTimeout 横幅读取超时，服务端通常会在数百毫秒内返回欢迎信息。
	bannerReadTimeout = 400 * time.Millisecond

	// bannerBufferSize 单次读取上限，足以覆盖 SSH、FTP、HTTP 的首段指纹。
	bannerBufferSize = 512

	// bannerDisplayLimit 最终保留的指纹长度，防止恶意服务用超长内容污染终端。
	bannerDisplayLimit = 256

	// maxSweepHosts 单次扫描的 IPv4 地址上限（约 /16），避免误扫 /8 拖垮手机。
	maxSweepHosts = 1 << 16
)

var (
	// bannerPool 复用横幅读取缓冲区，避免每次抓取都分配新内存。
	// 池中存放数组指针而不是切片，避免切片头在接口装箱时逃逸到堆上。
	bannerPool = sync.Pool{
		New: func() any {
			return new([bannerBufferSize]byte)
		},
	}

	// defaultScanPorts 战术侦察常用端口：SSH、HTTP、HTTPS、SMB、RDP。
	defaultScanPorts = [...]uint16{22, 80, 443, 445, 3389}

	// httpProbe 针对明文 HTTP 端口的最小 HEAD 探针。
	// 包级字节切片只初始化一次，扫描过程中不产生额外分配。
	httpProbe = []byte("HEAD / HTTP/1.0\r\n\r\n")

	// 编译期校验 Scanner 是否实现 LocalRecon，防止后续重构破坏接口签名。
	_ LocalRecon = (*Scanner)(nil)
)

// LocalRecon 定义本地网络侦察接口；Phase 3 先实现并发端口扫描与服务指纹抓取。
type LocalRecon interface {
	ConcurrentSweep(ctx context.Context, cidr string) ([]string, error)
	GrabBanner(ctx context.Context, targetIP string, port int) (string, error)
}

// Scanner 是 LocalRecon 的默认实现，零值即可安全并发使用。
type Scanner struct{}

// scanTask 用紧凑结构表示一个扫描任务，减少通道传输与堆积开销。
type scanTask struct {
	ip   uint32
	port uint16
}

/*
NewScanner 创建一个可以直接用于并发扫描的侦察器。
Scanner 为零值安全类型，返回指针是为了满足 LocalRecon 的接口实现方式。

参数:
  - 无。

返回:
  - *Scanner: 已就绪的扫描器实例。
*/
func NewScanner() *Scanner {
	return &Scanner{}
}

/*
ConcurrentSweep 启动针对目标网段的高并发、低延迟扫描引擎。
此方法使用固定大小的 Worker Pool 限制协程数量，
并利用极短超时避免被丢弃数据包的防火墙长期挂起。
为保护移动端资源，单次扫描最多处理约 /16 个 IPv4 地址。

参数:
  - ctx (context.Context): 全局上下文，用于捕获终止信号并执行安全退出。
  - cidr (string): 需要探测的目标 IPv4 子网，例如 "192.168.1.0/24"。

返回:
  - []string: 探测到的开放端点列表，格式为 "ip:port"；取消时保留已发现的部分结果。
  - error: CIDR 解析失败、范围过大或上下文被取消时返回错误。
*/
func (s *Scanner) ConcurrentSweep(ctx context.Context, cidr string) ([]string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		logger.Warn("CIDR 解析失败：%v", err)
		return nil, fmt.Errorf("解析 CIDR %q 失败: %w", cidr, err)
	}

	start, end, total, err := ipv4Range(network)
	if err != nil {
		logger.Warn("无法计算扫描范围：%v", err)
		return nil, err
	}
	if total > maxSweepHosts {
		logger.Warn("目标范围包含 %d 个地址，超过单次扫描上限 %d", total, maxSweepHosts)
		return nil, fmt.Errorf("目标范围过大：%d 个地址，上限为 %d", total, maxSweepHosts)
	}

	logger.Info("开始并发扫描 %s：%d 个可用地址 × %d 个端口", network.String(), total, len(defaultScanPorts))
	logger.Debug("扫描参数：工作协程=%d，连接超时=%v，横幅超时=%v", workerPoolSize, dialTimeout, bannerReadTimeout)

	jobs := make(chan scanTask, jobQueueSize)
	results := make(chan string, resultQueueSize)

	var wg sync.WaitGroup

	// 启动固定大小的工作协程池；整个扫描期间协程数量保持不变。
	for i := 0; i < workerPoolSize; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanWorker(ctx, jobs, results)
		}()
	}

	// 生产者按需生成 IP 与端口，不把整个网段展开到内存中。
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(jobs)
		feedTasks(ctx, start, end, jobs)
	}()

	// 所有生产者与消费者退出后关闭结果通道，主协程据此判断扫描正常结束。
	go func() {
		wg.Wait()
		close(results)
	}()

	found := make([]string, 0, 32)
	for {
		select {
		case <-ctx.Done():
			// 等待所有协程退出后再返回，确保取消扫描时不会遗留协程。
			wg.Wait()
			logger.Warn("扫描已取消，保留已发现的 %d 个开放端点", len(found))
			return found, ctx.Err()
		case endpoint, ok := <-results:
			if !ok {
				sort.Strings(found)
				logger.Info("扫描结束，共发现 %d 个开放端点", len(found))
				return found, nil
			}
			found = append(found, endpoint)
		}
	}
}

/*
GrabBanner 与指定 IP 和端口建立短连接，并读取服务端返回的首段横幅。
该方法用于服务指纹识别，例如识别 "SSH-2.0-OpenSSH"。
对 80 端口会发送最小 HEAD 探针，以诱导明文 HTTP 服务返回响应头。
若端口开放但服务端不主动发送数据，则返回空字符串和 nil。

参数:
  - ctx (context.Context): 全局上下文，取消时会立即关闭连接。
  - targetIP (string): 目标 IPv4 或 IPv6 地址。
  - port (int): 目标端口，有效范围为 1-65535。

返回:
  - string: 清洗后的服务横幅；服务端未返回数据时为空字符串。
  - error: IP 或端口非法、连接失败或上下文取消时返回错误。
*/
func (s *Scanner) GrabBanner(ctx context.Context, targetIP string, port int) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("端口超出范围: %d", port)
	}

	ip := net.ParseIP(targetIP)
	if ip == nil {
		return "", fmt.Errorf("非法 IP 地址: %q", targetIP)
	}

	// 规范化 IPv4 映射地址，避免输出 ::ffff: 前缀；IPv6 使用标准方括号格式。
	host := ip.String()
	if ip4 := ip.To4(); ip4 != nil {
		host = ip4.String()
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	logger.Debug("抓取服务指纹：%s", addr)
	banner, err := grabBanner(ctx, addr, uint16(port))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", fmt.Errorf("连接 %s 失败: %w", addr, err)
	}

	logOpenService(addr, banner)
	return banner, nil
}

/*
feedTasks 以流式方式向任务通道投放 IP 与端口组合。
该函数不会把整个网段展开为切片，从而把内存占用控制在常数级别。

参数:
  - ctx (context.Context): 用于在取消时立即停止投放。
  - start (uint32): 起始 IPv4 地址。
  - end (uint32): 结束 IPv4 地址，包含在扫描范围内。
  - jobs (chan<- scanTask): 工作协程消费的任务通道。

返回:
  - 无。
*/
func feedTasks(ctx context.Context, start, end uint32, jobs chan<- scanTask) {
	if start > end {
		return
	}

	for ip := start; ; ip++ {
		for _, port := range defaultScanPorts {
			select {
			case <-ctx.Done():
				return
			case jobs <- scanTask{ip: ip, port: port}:
			}
		}
		if ip == end {
			return
		}
	}
}

/*
scanWorker 是固定工作池中的消费者，负责拨号、抓取横幅并上报开放端点。
函数内部不会创建任何子协程，确保整个扫描过程的协程总数恒定。

参数:
  - ctx (context.Context): 全局上下文。
  - jobs (<-chan scanTask): 待扫描任务通道。
  - results (chan<- string): 开放端点结果通道。

返回:
  - 无。
*/
func scanWorker(ctx context.Context, jobs <-chan scanTask, results chan<- string) {
	// 地址缓冲区位于协程栈上循环复用，避免每个任务都调用 fmt.Sprintf。
	var addrBuf [21]byte

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-jobs:
			if !ok {
				return
			}

			addr := formatEndpoint(task.ip, task.port, addrBuf[:])
			banner, err := grabBanner(ctx, addr, task.port)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				// 端口关闭、被过滤或超时都是扫描常态，不打印日志以免刷屏。
				continue
			}

			logOpenService(addr, banner)

			select {
			case <-ctx.Done():
				return
			case results <- addr:
			}
		}
	}
}

/*
formatEndpoint 将紧凑的 IPv4 整数与端口格式化为 "a.b.c.d:port"。
它直接复用调用方缓冲区，避免 fmt.Sprintf 的反射与多次临时分配。

参数:
  - ip (uint32): IPv4 地址的整数表示。
  - port (uint16): 目标端口。
  - buf ([]byte): 调用方提供的可复用缓冲区，容量至少 21 字节。

返回:
  - string: 格式化后的端点字符串；字符串转换会产生唯一一次必要分配。
*/
func formatEndpoint(ip uint32, port uint16, buf []byte) string {
	buf = strconv.AppendUint(buf[:0], uint64(ip>>24), 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip>>16)&0xff, 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip>>8)&0xff, 10)
	buf = append(buf, '.')
	buf = strconv.AppendUint(buf, uint64(ip)&0xff, 10)
	buf = append(buf, ':')
	buf = strconv.AppendUint(buf, uint64(port), 10)
	return string(buf)
}

/*
dialContext 在微超时约束下建立 TCP 连接。
当上下文不可取消时走 net.DialTimeout 的最短路径；
当上下文可取消时改用 DialContext，以便收到取消信号后立即中断拨号，
同时避免为每个连接额外创建看门狗协程。

参数:
  - ctx (context.Context): 全局上下文。
  - addr (string): 目标 "ip:port" 地址。

返回:
  - net.Conn: 已建立的 TCP 连接。
  - error: 超时、拒绝连接或上下文取消时返回错误。
*/
func dialContext(ctx context.Context, addr string) (net.Conn, error) {
	if ctx.Done() == nil {
		return net.DialTimeout("tcp", addr, dialTimeout)
	}

	dialer := net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: -1, // 短连接扫描关闭 TCP 保活，减少移动端定时器开销
	}
	return dialer.DialContext(ctx, "tcp", addr)
}

/*
grabBanner 在已格式化的地址上执行一次短连接并读取服务横幅。
成功连接但读取失败时返回空字符串和 nil，因为端口开放本身已经是有效情报。
读取缓冲区来自 sync.Pool，并在原地完成清洗，避免每次抓取都分配新内存。

参数:
  - ctx (context.Context): 全局上下文。
  - addr (string): 已格式化的 "ip:port" 地址。
  - port (uint16): 目标端口，用于决定是否发送 HTTP 探针。

返回:
  - string: 清洗后的服务横幅。
  - error: 连接失败或上下文取消时返回错误。
*/
func grabBanner(ctx context.Context, addr string, port uint16) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	conn, err := dialContext(ctx, addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// 上下文取消时主动关闭连接，立即唤醒阻塞中的 Write 或 Read。
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
	})
	defer stop()

	// 读写共享一个微超时；若上下文的截止时间更早，则优先服从上下文。
	deadline := time.Now().Add(bannerReadTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", ctxErr
		}
		return "", nil
	}

	// 明文 HTTP 不会主动说话，用最小 HEAD 请求诱导响应；其余端口保持被动读取。
	if port == 80 {
		if _, err := conn.Write(httpProbe); err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return "", ctxErr
			}
			// 连接已经建立，写入失败也说明端口开放，只是拿不到指纹。
			return "", nil
		}
	}

	buf := bannerPool.Get().(*[bannerBufferSize]byte)
	defer bannerPool.Put(buf)

	n, readErr := conn.Read(buf[:])
	if ctxErr := ctx.Err(); ctxErr != nil {
		return "", ctxErr
	}
	if n > 0 {
		return sanitizeBanner(buf[:n]), nil
	}
	if readErr != nil {
		// 连接成功即代表端口开放；读取超时或对端不发送数据时返回空指纹。
		return "", nil
	}
	return "", nil
}

/*
logOpenService 统一输出开放端口情报。
拿到横幅时展示指纹，否则只报告端口开放，避免同一种事件出现多种日志格式。

参数:
  - addr (string): 开放端点。
  - banner (string): 清洗后的服务横幅。

返回:
  - 无。
*/
func logOpenService(addr, banner string) {
	if banner == "" {
		logger.Success("%s 端口开放（服务端未返回横幅）", addr)
		return
	}
	logger.Success("%s 端口开放 | 指纹: %s", addr, banner)
}

/*
sanitizeBanner 就地清洗服务横幅。
只保留可打印 ASCII，把换行折叠为空格，并把控制字符替换为点，
防止恶意服务通过 ANSI 转义序列污染 Termux 终端。

参数:
  - raw ([]byte): 从连接读取到的原始字节，函数会原地修改。

返回:
  - string: 截断并清洗后的横幅。
*/
func sanitizeBanner(raw []byte) string {
	if len(raw) > bannerDisplayLimit {
		raw = raw[:bannerDisplayLimit]
	}

	end := 0
	for _, b := range raw {
		switch {
		case b == '\r':
			// 丢弃回车，避免终端光标回到行首覆盖已有日志。
		case b == '\n' || b == '\t':
			raw[end] = ' '
			end++
		case b >= 0x20 && b <= 0x7e:
			raw[end] = b
			end++
		default:
			raw[end] = '.'
			end++
		}
	}

	// 去掉尾部空白与占位点，让指纹在紧凑的终端宽度内保持可读。
	for end > 0 && (raw[end-1] == ' ' || raw[end-1] == '.') {
		end--
	}
	return string(raw[:end])
}

/*
ipv4Range 计算 CIDR 中真正可扫描的主机闭区间。
/31 与 /32 按 RFC 3021 保留全部地址，其他前缀剔除网络地址与广播地址。

参数:
  - network (*net.IPNet): 已解析的 IPv4 网络。

返回:
  - start (uint32): 起始地址。
  - end (uint32): 结束地址，包含在扫描范围内。
  - total (uint64): 可用地址总数。
  - err (error): 非 IPv4 或掩码非法时返回错误。
*/
func ipv4Range(network *net.IPNet) (start, end uint32, total uint64, err error) {
	ip4 := network.IP.To4()
	if ip4 == nil {
		return 0, 0, 0, fmt.Errorf("当前仅支持 IPv4 CIDR: %s", network.String())
	}
	if len(network.Mask) != net.IPv4len {
		return 0, 0, 0, fmt.Errorf("非法 IPv4 掩码: %s", network.String())
	}

	ones, bits := network.Mask.Size()
	if bits != 32 {
		return 0, 0, 0, fmt.Errorf("非法 IPv4 CIDR: %s", network.String())
	}

	mask := binary.BigEndian.Uint32(network.Mask)
	first := binary.BigEndian.Uint32(ip4) & mask
	last := first | ^mask

	if ones >= 31 {
		start, end = first, last
	} else {
		start, end = first+1, last-1
	}

	total = uint64(end-start) + 1
	return start, end, total, nil
}
