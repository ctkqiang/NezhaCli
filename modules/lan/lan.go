// lan 模块枚举本机接口、局域网网段并通过 TCP 探测发现活跃主机。
package lan

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/netutil"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	"github.com/ctkqiang/nezha_cli/pkg/recon"
	"github.com/ctkqiang/nezha_cli/pkg/system"
)

const (
	// DefaultPorts 是主机存活探测使用的端口集合。
	DefaultPorts = "22,80,443,445,62078"

	// maxLANHosts 是单次发现的最大地址数，约等于 /22 网段。
	maxLANHosts = 1024

	// minWorkers 与 maxWorkers 限制主机探测并发。
	minWorkers = 8
	maxWorkers = 256
)

// lanTask 描述一个待探测的局域网主机。
type lanTask struct {
	host  string
	ports []uint16
}

// lanResult 描述一个活跃主机及其开放端口。
type lanResult struct {
	host  string
	ports []int
}

// Module 是局域网发现模块。
type Module struct{}

/*
New 创建局域网发现模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回局域网发现模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "lan",
		Aliases:  []string{"local", "neighbors"},
		Category: modulekit.CategoryRecon,
		Summary:  "本机接口、局域网网段与活跃主机发现",
		Description: "枚举网络接口与地址，自动推断当前局域网 /24 网段，\n" +
			"并对网段内主机执行常见端口的 TCP 存活探测。\n" +
			"不使用 ARP 原始套接字，因此在无 Root 的 Termux 上可运行；\n" +
			"只开放 UDP 或被防火墙静默丢弃的主机可能漏报。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("CIDR", "自定义网段；留空自动推断本机 /24", false, ""),
			modulekit.Option("DISCOVER", "是否执行活跃主机探测（true/false）", false, "true"),
			modulekit.Option("PORTS", "存活探测端口", false, DefaultPorts),
			modulekit.Option("TIMEOUT", "单次连接超时", false, "300ms"),
			modulekit.Option("WORKERS", "并发探测主机数", false, "128"),
		},
	}
}

/*
Run 输出接口信息，并按需执行局域网活跃主机发现。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法、网段推断失败或执行被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	interfaces, interfaceErr := system.Interfaces()
	if interfaceErr != nil {
		logger.Warn("读取网络接口失败：%v", interfaceErr)
	}

	localAddresses := make(map[string]struct{}, 8)
	rows := make([][]string, 0, len(interfaces))
	for _, iface := range interfaces {
		for _, address := range iface.Addresses {
			if ip, _, err := net.ParseCIDR(address); err == nil {
				localAddresses[ip.String()] = struct{}{}
			}
		}
		state := "down"
		if iface.Up {
			state = "up"
		}
		rows = append(rows, []string{
			iface.Name,
			dash(iface.MAC),
			state,
			boolText(iface.Wireless),
			modulekit.Etc(strings.Join(iface.Addresses, ", "), 50),
		})
	}

	modulekit.Section(out, fmt.Sprintf("网络接口 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未读取到网络接口。")
	} else {
		modulekit.Table(out, []string{"接口", "MAC", "状态", "无线", "地址"}, rows, 48)
	}

	if !options.Bool("DISCOVER", true) {
		return nil
	}

	cidr := strings.TrimSpace(options.Get("CIDR"))
	if cidr == "" {
		detected, err := system.LocalCIDR()
		if err != nil {
			if interfaceErr != nil {
				return interfaceErr
			}
			return err
		}
		cidr = detected
	}

	ports, err := recon.ParsePorts(options.String("PORTS", DefaultPorts))
	if err != nil {
		return err
	}
	timeout := options.Duration("TIMEOUT", 300*time.Millisecond)
	workers := options.Int("WORKERS", 128)
	if workers < minWorkers {
		workers = minWorkers
	}
	if workers > maxWorkers {
		workers = maxWorkers
	}

	hosts, err := netutil.ExpandHosts(cidr, maxLANHosts)
	if err != nil {
		return err
	}

	modulekit.Section(out, "发现配置")
	modulekit.KeyValues(out, [][2]string{
		{"网段", cidr},
		{"地址数", strconv.Itoa(len(hosts))},
		{"端口", options.String("PORTS", DefaultPorts)},
		{"并发", strconv.Itoa(workers)},
		{"超时", timeout.String()},
	}, 60)

	started := time.Now()
	active := discoverHosts(ctx, hosts, ports, workers, timeout)
	sort.Slice(active, func(left int, right int) bool {
		leftIP := net.ParseIP(active[left].host)
		rightIP := net.ParseIP(active[right].host)
		return bytes.Compare(leftIP.To4(), rightIP.To4()) < 0
	})

	resultRows := make([][]string, 0, len(active))
	for _, item := range active {
		note := "-"
		if _, isLocal := localAddresses[item.host]; isLocal {
			note = "本机"
		}
		resultRows = append(resultRows, []string{
			item.host,
			joinPorts(item.ports),
			note,
		})
	}

	modulekit.Section(out, fmt.Sprintf("活跃主机 %d", len(resultRows)))
	if len(resultRows) == 0 {
		fmt.Fprintln(out, "未发现活跃主机。可尝试增加 PORTS、提高 TIMEOUT 或指定 CIDR。")
		return nil
	}
	modulekit.Table(out, []string{"主机", "开放端口", "备注"}, resultRows, 48)
	logger.Info("局域网发现完成：%d 台活跃主机，耗时 %s", len(resultRows), time.Since(started).Round(time.Millisecond))
	return nil
}

/*
discoverHosts 并发探测网段内主机的常见端口，任一端口开放即视为活跃。

参数:
  - ctx (context.Context): 执行上下文。
  - hosts ([]net.IP): 待探测地址。
  - ports ([]uint16): 探测端口。
  - workers (int): 并发主机数。
  - timeout (time.Duration): 单次连接超时。

返回:
  - []lanResult: 活跃主机与开放端口。
*/
func discoverHosts(ctx context.Context, hosts []net.IP, ports []uint16, workers int, timeout time.Duration) []lanResult {
	jobs := make(chan lanTask, workers)
	results := make(chan lanResult, workers)
	var waitGroup sync.WaitGroup

	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for task := range jobs {
				open := make([]int, 0, len(task.ports))
				for _, port := range task.ports {
					select {
					case <-ctx.Done():
						return
					default:
					}
					dialer := net.Dialer{Timeout: timeout}
					connection, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(task.host, strconv.Itoa(int(port))))
					if err != nil {
						continue
					}
					_ = connection.Close()
					open = append(open, int(port))
				}
				if len(open) > 0 {
					results <- lanResult{host: task.host, ports: open}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			select {
			case <-ctx.Done():
				return
			case jobs <- lanTask{host: host.String(), ports: ports}:
			}
		}
	}()

	go func() {
		waitGroup.Wait()
		close(results)
	}()

	active := make([]lanResult, 0, 16)
	for {
		select {
		case <-ctx.Done():
			return active
		case item, ok := <-results:
			if !ok {
				return active
			}
			active = append(active, item)
		}
	}
}

/*
joinPorts 把端口切片格式化为逗号分隔字符串。

参数:
  - ports ([]int): 端口列表。

返回:
  - string: 逗号分隔端口；空列表返回 “-”。
*/
func joinPorts(ports []int) string {
	if len(ports) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ", ")
}

/*
dash 在值为空时返回占位符。

参数:
  - value (string): 原始值。

返回:
  - string: 原值或 “-”。
*/
func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

/*
boolText 把布尔值转换为中文状态。

参数:
  - value (bool): 布尔值。

返回:
  - string: “是”或“否”。
*/
func boolText(value bool) string {
	if value {
		return "是"
	}
	return "否"
}
