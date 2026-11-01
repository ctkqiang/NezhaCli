// portscan 模块实现局域网并发 TCP 端口扫描与服务指纹抓取。
package portscan

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/netutil"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	"github.com/ctkqiang/nezha_cli/pkg/recon"
)

// Module 是 TCP 端口扫描模块。
type Module struct{}

/*
New 创建端口扫描模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回端口扫描模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "portscan",
		Aliases:  []string{"scan", "port_scan"},
		Category: modulekit.CategoryRecon,
		Summary:  "并发 TCP 端口扫描与服务横幅",
		Description: "对单个主机、域名或 CIDR 执行并发 TCP connect 端口扫描。\n" +
			"适用于快速盘点资产开放端口、定位内网服务与验证防火墙策略。\n" +
			"纯 Go 实现无外部依赖，不使用 raw socket，在无 Root 的 Termux 上可运行；\n" +
			"并发硬上限 512，发现开放端口后可配合 service 模块识别服务横幅。",
		Usage:  "use portscan\nset TARGET 192.168.1.0/24\nset PORTS 1-1024\nrun",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("TARGET", "待扫描的主机、域名或 CIDR；多个用逗号分隔并逐项展开。", true, ""),
			modulekit.Option("PORTS", "目标端口；支持逗号列表与 1-1024 区间写法；非法格式报错。", false, recon.DefaultPortString),
			modulekit.Option("TIMEOUT", "单次连接与横幅读取超时；支持 400ms、15s 等 Go 时长格式。", false, "400ms"),
			modulekit.Option("WORKERS", "并发扫描协程数；超出上限自动截断至 512；过大会拖慢设备。", false, "256"),
			modulekit.Option("BANNER", "是否读取服务横幅；取值 true/false；关闭后仅探测端口开放。", false, "true"),
		},
		References: []string{"https://github.com/ctkqiang/NezhaCli", "https://attack.mitre.org/"},
	}
}

/*
Run 解析目标与端口后执行扫描，并把开放端点写入输出目标。

参数:
  - ctx (context.Context): 执行上下文，Ctrl+C 时取消扫描。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法、目标解析失败或扫描被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	target := options.Get("TARGET")
	ports, err := recon.ParsePorts(options.String("PORTS", recon.DefaultPortString))
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return fmt.Errorf("端口列表不能为空")
	}

	timeout := options.Duration("TIMEOUT", recon.DefaultDialTimeout)
	workers := options.Int("WORKERS", recon.DefaultWorkerCount)
	readBanner := options.Bool("BANNER", true)

	cidrs, err := netutil.ResolveTargets(ctx, target, netutil.MaxExpandedHosts)
	if err != nil {
		return err
	}

	scanner := &recon.Scanner{
		Ports:         ports,
		Workers:       workers,
		DialTimeout:   timeout,
		BannerTimeout: timeout,
	}
	if !readBanner {
		scanner.BannerTimeout = time.Nanosecond
	}

	modulekit.Section(out, "扫描配置")
	modulekit.KeyValues(out, [][2]string{
		{"目标", strings.Join(cidrs, ", ")},
		{"端口", options.String("PORTS", recon.DefaultPortString)},
		{"并发", fmt.Sprintf("%d", workers)},
		{"超时", timeout.String()},
		{"横幅", fmt.Sprintf("%t", readBanner)},
	}, 60)

	started := time.Now()
	findings := make([]recon.Finding, 0, 32)
	for _, cidr := range cidrs {
		partial, err := scanner.Scan(ctx, cidr)
		findings = append(findings, partial...)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
	}

	sort.Slice(findings, func(left int, right int) bool {
		return findings[left].Endpoint < findings[right].Endpoint
	})

	rows := make([][]string, 0, len(findings))
	for _, finding := range findings {
		banner := strings.TrimSpace(finding.Banner)
		if banner == "" {
			banner = "-"
		}
		rows = append(rows, []string{finding.Endpoint, modulekit.Etc(banner, 52)})
	}

	modulekit.Section(out, fmt.Sprintf("开放端点 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未发现开放端口。可尝试扩大 PORTS 或提高 TIMEOUT。")
	} else {
		modulekit.Table(out, []string{"端点", "服务横幅"}, rows, 56)
	}

	logger.Info("端口扫描完成：%d 个端点，耗时 %s", len(rows), time.Since(started).Round(time.Millisecond))
	return nil
}
