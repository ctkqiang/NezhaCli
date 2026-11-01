// service 模块对指定主机与端口执行服务横幅识别。
package service

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/netutil"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	"github.com/ctkqiang/nezha_cli/pkg/recon"
)

const (
	// DefaultPorts 是服务识别默认探测的常见端口。
	DefaultPorts = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443"

	// maxHosts 是单次服务识别的地址上限，避免移动端一次性建立过多连接。
	maxHosts = 256

	// minWorkers 与 maxWorkers 限制并发拨号数量。
	minWorkers = 8
	maxWorkers = 128
)

// probeTask 描述一个待探测的主机端口组合。
type probeTask struct {
	host string
	port int
}

// probeResult 描述一个主机端口的探测结果。
type probeResult struct {
	host   string
	port   int
	banner string
	err    error
}

// Module 是服务指纹识别模块。
type Module struct{}

/*
New 创建服务指纹识别模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回服务指纹识别模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "service",
		Aliases:  []string{"banner", "fingerprint"},
		Category: modulekit.CategoryRecon,
		Summary:  "明文服务横幅与协议指纹识别",
		Description: "对指定主机与端口并发建立 TCP 连接并读取首段数据，识别服务类型。\n" +
			"适用于 portscan 发现开放端口后确认服务归属，或手工验证可疑横幅。\n" +
			"按 SSH、HTTP、FTP、SMTP、MySQL、Redis 等特征归类，纯 Go 实现无外部依赖；\n" +
			"只读取主动返回或最小 HTTP 探针触发的明文横幅，不发送任何漏洞载荷。",
		Usage:  "use service\nset TARGET example.com\nset PORTS 80,443,3306\nrun",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("TARGET", "目标主机、域名或 CIDR；多个用逗号分隔；展开总量上限 256。", true, ""),
			modulekit.Option("PORTS", "待识别端口；支持逗号与区间写法；默认覆盖常见服务端口。", false, DefaultPorts),
			modulekit.Option("TIMEOUT", "单次连接与横幅读取超时；支持 Go 时长格式；影响识别成功率。", false, "600ms"),
			modulekit.Option("WORKERS", "并发拨号协程数；自动限制在 8 至 128 之间；过大被截断。", false, "48"),
		},
		References: []string{"https://github.com/ctkqiang/NezhaCli", "https://attack.mitre.org/"},
	}
}

/*
Run 解析目标并并发抓取服务横幅。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法、目标解析失败或执行被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	ports, err := recon.ParsePorts(options.String("PORTS", DefaultPorts))
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return fmt.Errorf("端口列表不能为空")
	}

	hosts, err := resolveHosts(ctx, options.Get("TARGET"))
	if err != nil {
		return err
	}

	timeout := options.Duration("TIMEOUT", 600*time.Millisecond)
	workers := options.Int("WORKERS", 48)
	if workers < minWorkers {
		workers = minWorkers
	}
	if workers > maxWorkers {
		workers = maxWorkers
	}

	modulekit.Section(out, "识别配置")
	modulekit.KeyValues(out, [][2]string{
		{"目标", strings.Join(hosts, ", ")},
		{"端口", options.String("PORTS", DefaultPorts)},
		{"并发", fmt.Sprintf("%d", workers)},
		{"超时", timeout.String()},
	}, 60)

	scanner := &recon.Scanner{
		Ports:         ports,
		DialTimeout:   timeout,
		BannerTimeout: timeout,
	}

	jobs := make(chan probeTask, workers*2)
	results := make(chan probeResult, workers*2)
	var waitGroup sync.WaitGroup

	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for task := range jobs {
				banner, err := scanner.GrabBanner(ctx, task.host, task.port)
				results <- probeResult{host: task.host, port: task.port, banner: banner, err: err}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- probeTask{host: host, port: int(port)}:
				}
			}
		}
	}()

	go func() {
		waitGroup.Wait()
		close(results)
	}()

	collected := make([]probeResult, 0, len(hosts)*len(ports))
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				return printResults(out, collected)
			}
			if result.err == nil {
				collected = append(collected, result)
			}
		}
	}
}

/*
resolveHosts 把目标展开为 IPv4 地址列表，并限制总量。

参数:
  - ctx (context.Context): 解析上下文。
  - target (string): 原始目标字符串。

返回:
  - []string: 去重后的 IPv4 地址列表。
  - error: 目标非法或数量超限时返回错误。
*/
func resolveHosts(ctx context.Context, target string) ([]string, error) {
	cidrs, err := netutil.ResolveTargets(ctx, target, maxHosts)
	if err != nil {
		return nil, err
	}

	seen := make(map[string]struct{}, maxHosts)
	hosts := make([]string, 0, maxHosts)
	for _, cidr := range cidrs {
		addresses, err := netutil.ExpandHosts(cidr, maxHosts)
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			host := address.String()
			if _, exists := seen[host]; exists {
				continue
			}
			seen[host] = struct{}{}
			hosts = append(hosts, host)
			if len(hosts) >= maxHosts {
				return hosts, nil
			}
		}
	}
	return hosts, nil
}

/*
printResults 按主机与端口排序并输出服务识别结果。

参数:
  - out (io.Writer): 结果输出目标。
  - results ([]probeResult): 已收集的成功探测结果。

返回:
  - error: 始终返回 nil。
*/
func printResults(out io.Writer, results []probeResult) error {
	sort.Slice(results, func(left int, right int) bool {
		if results[left].host == results[right].host {
			return results[left].port < results[right].port
		}
		return results[left].host < results[right].host
	})

	rows := make([][]string, 0, len(results))
	for _, result := range results {
		banner := strings.TrimSpace(result.banner)
		if banner == "" {
			banner = "-"
		}
		rows = append(rows, []string{
			result.host,
			fmt.Sprintf("%d", result.port),
			fingerprint(result.port, banner),
			modulekit.Etc(banner, 44),
		})
	}

	modulekit.Section(out, fmt.Sprintf("开放服务 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未发现可识别的开放服务。")
		return nil
	}
	modulekit.Table(out, []string{"主机", "端口", "指纹", "横幅"}, rows, 46)
	logger.Info("服务识别完成：%d 个开放端口", len(rows))
	return nil
}

/*
fingerprint 根据端口与横幅推断服务类型。

参数:
  - port (int): 目标端口。
  - banner (string): 服务横幅。

返回:
  - string: 服务名称。
*/
func fingerprint(port int, banner string) string {
	lower := strings.ToLower(banner)
	switch {
	case strings.Contains(lower, "ssh-"):
		return "SSH"
	case strings.Contains(lower, "http/") || strings.Contains(lower, "<html") || strings.Contains(lower, "server:"):
		return "HTTP"
	case strings.Contains(lower, "ftp"):
		return "FTP"
	case strings.Contains(lower, "smtp"):
		return "SMTP"
	case strings.Contains(lower, "imap"):
		return "IMAP"
	case strings.Contains(lower, "pop3"):
		return "POP3"
	case strings.Contains(lower, "mysql"):
		return "MySQL"
	case strings.Contains(lower, "redis"):
		return "Redis"
	case strings.Contains(lower, "telnet"):
		return "Telnet"
	case port == 445 || port == 139:
		return "SMB"
	case port == 3389:
		return "RDP"
	case port == 53:
		return "DNS"
	case port == 443 || port == 8443:
		return "TLS/HTTPS"
	case port == 3306:
		return "MySQL"
	case port == 5432:
		return "PostgreSQL"
	case port == 6379:
		return "Redis"
	case port == 22:
		return "SSH"
	default:
		return "未知"
	}
}
