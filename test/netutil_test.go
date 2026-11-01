package test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/netutil"
)

/*
TestNetutilSplitTargets 验证多分隔符拆分与去重。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilSplitTargets(t *testing.T) {
	targets := netutil.SplitTargets("10.0.0.1, 10.0.0.2;10.0.0.1\nexample.com")
	if len(targets) != 3 {
		t.Fatalf("目标数量错误: %v", targets)
	}
	if targets[0] != "10.0.0.1" || targets[1] != "10.0.0.2" || targets[2] != "example.com" {
		t.Fatalf("目标顺序错误: %v", targets)
	}
	if got := netutil.SplitTargets("   "); len(got) != 0 {
		t.Fatalf("空输入应返回空切片: %v", got)
	}
}

/*
TestNetutilHostCount 验证 CIDR 地址总数计算。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilHostCount(t *testing.T) {
	cases := map[string]int{
		"10.0.0.0/32": 1,
		"10.0.0.0/30": 4,
		"10.0.0.0/24": 256,
		"10.0.0.0/16": 65536,
	}
	for cidr, want := range cases {
		got, err := netutil.HostCount(cidr)
		if err != nil {
			t.Fatalf("HostCount(%s) 返回错误: %v", cidr, err)
		}
		if got != want {
			t.Fatalf("HostCount(%s) = %d，期望 %d", cidr, got, want)
		}
	}

	if _, err := netutil.HostCount("not-a-cidr"); err == nil {
		t.Fatal("非法 CIDR 应返回错误")
	}
}

/*
TestNetutilExpandHosts 验证 CIDR 展开、边界与上限拦截。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilExpandHosts(t *testing.T) {
	hosts, err := netutil.ExpandHosts("192.168.1.0/30", 0)
	if err != nil {
		t.Fatalf("展开失败: %v", err)
	}
	want := []string{"192.168.1.0", "192.168.1.1", "192.168.1.2", "192.168.1.3"}
	if len(hosts) != len(want) {
		t.Fatalf("地址数量错误: %d", len(hosts))
	}
	for index, host := range hosts {
		if host.String() != want[index] {
			t.Fatalf("第 %d 个地址错误: %s", index, host)
		}
	}

	if _, err := netutil.ExpandHosts("10.0.0.0/8", 256); err == nil {
		t.Fatal("超出上限应返回错误")
	}
}

/*
TestNetutilResolveTargets 验证 IP、CIDR 与域名输入的统一规范化。
域名解析使用本机解析器，仅验证 127.0.0.1 与显式地址，避免测试依赖外网。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilResolveTargets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cidrs, err := netutil.ResolveTargets(ctx, "127.0.0.1, 10.0.0.0/30", 0)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(cidrs) != 2 || cidrs[0] != "127.0.0.1/32" || cidrs[1] != "10.0.0.0/30" {
		t.Fatalf("规范化结果错误: %v", cidrs)
	}

	if _, err := netutil.ResolveTargets(ctx, "", 0); err == nil {
		t.Fatal("空目标应返回错误")
	}
	if _, err := netutil.ResolveTargets(ctx, "10.0.0.0/8", 256); err == nil {
		t.Fatal("超出地址上限应返回错误")
	}
	if _, err := netutil.ResolveTargets(ctx, "2001:db8::1", 0); err == nil {
		t.Fatal("IPv6 目标应被拒绝")
	}
}

/*
TestNetutilJoinHostPort 验证 IPv4 与 IPv6 的地址拼接。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilJoinHostPort(t *testing.T) {
	if got := netutil.JoinHostPort("example.com", 443); got != "example.com:443" {
		t.Fatalf("主机拼接错误: %s", got)
	}
	if got := netutil.JoinHostPort("::1", 80); got != "[::1]:80" {
		t.Fatalf("IPv6 拼接错误: %s", got)
	}
}

/*
TestNetutilNormalizeURL 验证协议补全与非法输入拦截。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilNormalizeURL(t *testing.T) {
	parsed, err := netutil.NormalizeURL("example.com/path", "https")
	if err != nil {
		t.Fatalf("URL 规范化失败: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host != "example.com" || parsed.Path != "/path" {
		t.Fatalf("规范化结果错误: %s", parsed.String())
	}

	if _, err := netutil.NormalizeURL("ftp://example.com", ""); err == nil {
		t.Fatal("非 HTTP 协议应被拒绝")
	}
	if _, err := netutil.NormalizeURL("   ", ""); err == nil {
		t.Fatal("空 URL 应返回错误")
	}
}

/*
TestNetutilParseMAC 验证 MAC 解析与长度校验。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilParseMAC(t *testing.T) {
	address, err := netutil.ParseMAC("AA:BB:CC:DD:EE:FF")
	if err != nil {
		t.Fatalf("MAC 解析失败: %v", err)
	}
	if address.String() != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("MAC 规范化错误: %s", address)
	}

	if _, err := netutil.ParseMAC("aa:bb:cc"); err == nil {
		t.Fatal("短 MAC 应返回错误")
	}
	if _, err := netutil.ParseMAC("zz:zz:zz:zz:zz:zz"); err == nil {
		t.Fatal("非法 MAC 应返回错误")
	}
	if _, err := netutil.ParseMAC("02:00:00:00:00:00:00:00"); err == nil {
		t.Fatal("8 字节 MAC 应被拒绝")
	}
}

/*
TestNetutilFirstIPv4 验证本地回环地址直接返回，不触发 DNS。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestNetutilFirstIPv4(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	address, err := netutil.FirstIPv4(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("FirstIPv4 失败: %v", err)
	}
	if address != "127.0.0.1" {
		t.Fatalf("地址错误: %s", address)
	}

	if _, err := netutil.FirstIPv4(ctx, "::1"); err == nil {
		t.Fatal("IPv6 地址应被拒绝")
	}
	if local := net.ParseIP(address); local == nil {
		t.Fatalf("返回内容不是 IP: %s", address)
	}
	if strings.TrimSpace(address) == "" {
		t.Fatal("地址不能为空")
	}
}
