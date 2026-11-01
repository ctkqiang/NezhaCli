package test

import (
	"context"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ctkqiang/nezha_cli/pkg/system"
)

/*
TestSystemCollectInfo 验证环境信息与当前进程一致。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestSystemCollectInfo(t *testing.T) {
	info := system.CollectInfo()

	if strings.TrimSpace(info.Hostname) == "" {
		t.Fatal("主机名不能为空")
	}
	if info.OS != runtime.GOOS || info.Arch != runtime.GOARCH {
		t.Fatalf("系统或架构错误: %s/%s", info.OS, info.Arch)
	}
	if !strings.HasPrefix(info.GoVersion, "go") {
		t.Fatalf("Go 版本异常: %s", info.GoVersion)
	}
	if info.UID != os.Getuid() {
		t.Fatalf("UID 错误: %d", info.UID)
	}
	if info.Root != (info.UID == 0) {
		t.Fatalf("Root 判定错误: %t", info.Root)
	}
	if strings.TrimSpace(info.Distro) == "" || strings.TrimSpace(info.Kernel) == "" {
		t.Fatalf("发行版或内核信息缺失: %+v", info)
	}
}

/*
TestSystemInterfaces 验证接口枚举结果结构；无网络接口时跳过。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestSystemInterfaces(t *testing.T) {
	interfaces, err := system.Interfaces()
	if err != nil {
		t.Skipf("当前环境无法枚举接口: %v", err)
	}
	for _, iface := range interfaces {
		if strings.TrimSpace(iface.Name) == "" {
			t.Fatalf("接口名称不能为空: %+v", iface)
		}
		for _, address := range iface.Addresses {
			if _, _, err := net.ParseCIDR(address); err != nil {
				t.Fatalf("接口地址格式错误: %s", address)
			}
		}
	}

	wireless, err := system.WirelessInterfaces()
	if err != nil {
		t.Fatalf("无线接口枚举失败: %v", err)
	}
	for _, iface := range wireless {
		if !iface.Wireless {
			t.Fatalf("无线接口标记错误: %+v", iface)
		}
	}

	if cidr, err := system.LocalCIDR(); err == nil {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			t.Fatalf("本机网段格式错误: %s", cidr)
		}
	}
}

/*
TestSystemCheckConnectivity 验证本地监听为连通、关闭端口为失败。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestSystemCheckConnectivity(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动监听失败: %v", err)
	}
	address := listener.Addr().String()
	listener.Close()

	// 关闭监听后端口不再接受连接，用于构造失败场景。
	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动第二个监听失败: %v", err)
	}
	closedAddress := closedListener.Addr().String()
	closedListener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := system.CheckConnectivity(ctx, []string{address, closedAddress}, 300*time.Millisecond)
	if len(results) != 2 {
		t.Fatalf("结果数量错误: %d", len(results))
	}
	if results[0].OK {
		t.Fatalf("已关闭端口不应连通: %+v", results[0])
	}
	if results[1].OK {
		t.Fatalf("已关闭端口不应连通: %+v", results[1])
	}
	if results[1].Error == "" {
		t.Fatalf("失败结果应包含错误: %+v", results[1])
	}
	if !strings.Contains(system.FormatConnectivity(results[1]), "失败") {
		t.Fatalf("失败格式化错误: %s", system.FormatConnectivity(results[1]))
	}
}

/*
TestSystemCheckConnectivitySuccess 验证活跃监听端口的连通结果与格式化。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestSystemCheckConnectivitySuccess(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动监听失败: %v", err)
	}
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results := system.CheckConnectivity(ctx, []string{listener.Addr().String()}, time.Second)
	if len(results) != 1 || !results[0].OK {
		t.Fatalf("本地监听应连通: %+v", results)
	}
	if results[0].Latency < 0 {
		t.Fatalf("延迟不能为负: %s", results[0].Latency)
	}
	if !strings.Contains(system.FormatConnectivity(results[0]), "连通") {
		t.Fatalf("连通格式化错误: %s", system.FormatConnectivity(results[0]))
	}
}

/*
TestSystemCheckConnectivityCanceled 验证取消上下文使探测失败。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestSystemCheckConnectivityCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	results := system.CheckConnectivity(ctx, []string{"127.0.0.1:1"}, time.Second)
	if len(results) != 1 || results[0].OK {
		t.Fatalf("已取消上下文不应连通: %+v", results)
	}
}

/*
TestSystemBluetoothAdapters 验证蓝牙枚举在无 sysfs 时返回明确错误。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestSystemBluetoothAdapters(t *testing.T) {
	adapters, err := system.BluetoothAdapters()
	if err != nil {
		if !strings.Contains(err.Error(), "蓝牙") {
			t.Fatalf("错误信息不可读: %v", err)
		}
		return
	}
	for _, adapter := range adapters {
		if !strings.HasPrefix(adapter.Path, "/sys/class/bluetooth/") {
			t.Fatalf("适配器路径错误: %+v", adapter)
		}
		if strings.TrimSpace(adapter.Name) == "" || strings.TrimSpace(adapter.Address) == "" {
			t.Fatalf("适配器信息不完整: %+v", adapter)
		}
	}
}
