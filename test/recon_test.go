package test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ctkqiang/nezha_cli/pkg/recon"
)

/*
TestReconParsePorts 验证端口列表、区间、去重与排序。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconParsePorts(t *testing.T) {
	ports, err := recon.ParsePorts("443, 22,80,22")
	if err != nil {
		t.Fatalf("解析端口失败: %v", err)
	}
	if len(ports) != 3 || ports[0] != 22 || ports[1] != 80 || ports[2] != 443 {
		t.Fatalf("端口去重排序错误: %v", ports)
	}

	ranged, err := recon.ParsePorts("20-22,80,22")
	if err != nil {
		t.Fatalf("解析端口区间失败: %v", err)
	}
	if len(ranged) != 4 || ranged[0] != 20 || ranged[1] != 21 || ranged[2] != 22 || ranged[3] != 80 {
		t.Fatalf("端口区间展开错误: %v", ranged)
	}

	invalid := []string{"", "0", "65536", "abc", "90-80", "1-", "-80", "1-70000"}
	for _, value := range invalid {
		if _, err := recon.ParsePorts(value); err == nil {
			t.Fatalf("非法端口 %q 应返回错误", value)
		}
	}
}

/*
TestReconDefaultPorts 验证默认端口副本不会被调用方污染。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconDefaultPorts(t *testing.T) {
	first := recon.DefaultPorts()
	if len(first) == 0 {
		t.Fatal("默认端口不能为空")
	}
	first[0] = 1

	second := recon.DefaultPorts()
	if second[0] == 1 {
		t.Fatalf("默认端口被调用方修改: %v", second)
	}
	if !strings.Contains(recon.DefaultPortString, "22") {
		t.Fatalf("默认端口字符串异常: %s", recon.DefaultPortString)
	}
}

/*
TestReconScanLocalListener 验证对本地监听端口的并发扫描命中。
只扫描 127.0.0.1/32，避免测试触碰外部网络。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconScanLocalListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动本地监听失败: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	scanner := &recon.Scanner{
		Ports:         []uint16{uint16(port)},
		Workers:       4,
		DialTimeout:   500 * time.Millisecond,
		BannerTimeout: 50 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	findings, err := scanner.Scan(ctx, "127.0.0.1/32")
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("应命中 1 个端点，实际 %d", len(findings))
	}
	want := "127.0.0.1:" + strconv.Itoa(port)
	if findings[0].Endpoint != want {
		t.Fatalf("端点错误: %s，期望 %s", findings[0].Endpoint, want)
	}

	endpoints, err := scanner.ConcurrentSweep(ctx, "127.0.0.1/32")
	if err != nil {
		t.Fatalf("ConcurrentSweep 失败: %v", err)
	}
	if len(endpoints) != 1 || endpoints[0] != want {
		t.Fatalf("兼容接口结果错误: %v", endpoints)
	}
}

/*
TestReconScanRejectsOversize 验证超过 /16 的扫描范围会被拒绝。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconScanRejectsOversize(t *testing.T) {
	scanner := &recon.Scanner{Ports: []uint16{80}, Workers: 1, DialTimeout: time.Millisecond}
	if _, err := scanner.Scan(context.Background(), "10.0.0.0/8"); err == nil {
		t.Fatal("超大网段应返回错误")
	}
	if _, err := scanner.Scan(context.Background(), "not-a-cidr"); err == nil {
		t.Fatal("非法 CIDR 应返回错误")
	}
}

/*
TestReconScanCanceled 验证已取消的上下文立即返回。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconScanCanceled(t *testing.T) {
	scanner := &recon.Scanner{Ports: []uint16{80}, Workers: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := scanner.Scan(ctx, "127.0.0.1/32"); err == nil {
		t.Fatal("已取消上下文应返回错误")
	}
}

/*
TestReconGrabBanner 验证本地服务横幅读取与清洗。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconGrabBanner(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动监听失败: %v", err)
	}
	defer listener.Close()

	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		_, _ = connection.Write([]byte("SSH-2.0-Nezha\r\n"))
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	scanner := &recon.Scanner{BannerTimeout: time.Second}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	banner, err := scanner.GrabBanner(ctx, "127.0.0.1", port)
	if err != nil {
		t.Fatalf("读取横幅失败: %v", err)
	}
	if !strings.Contains(banner, "SSH-2.0-Nezha") {
		t.Fatalf("横幅内容错误: %q", banner)
	}
	if strings.ContainsAny(banner, "\r\n") {
		t.Fatalf("横幅应清洗控制字符: %q", banner)
	}
}

/*
TestReconGrabBannerValidation 验证非法 IP 与端口。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconGrabBannerValidation(t *testing.T) {
	scanner := &recon.Scanner{}
	if _, err := scanner.GrabBanner(context.Background(), "not-an-ip", 80); err == nil {
		t.Fatal("非法 IP 应返回错误")
	}
	if _, err := scanner.GrabBanner(context.Background(), "127.0.0.1", 0); err == nil {
		t.Fatal("非法端口应返回错误")
	}
	if _, err := scanner.GrabBanner(context.Background(), "127.0.0.1", 70000); err == nil {
		t.Fatal("越界端口应返回错误")
	}
}

/*
TestReconLookupDNS 验证空域名拦截与本地域名解析。
仅查询 localhost，避免测试依赖公网 DNS。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestReconLookupDNS(t *testing.T) {
	if _, err := recon.LookupDNS(context.Background(), ""); err == nil {
		t.Fatal("空域名应返回错误")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	records, err := recon.LookupDNS(ctx, "localhost")
	if err != nil {
		t.Fatalf("localhost 解析失败: %v", err)
	}
	found := false
	for _, record := range records {
		if record.Type == "A" && len(record.Values) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("localhost 缺少 A 记录: %+v", records)
	}
}
