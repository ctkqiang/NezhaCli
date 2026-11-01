package system

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// InterfaceInfo 描述一个网络接口的地址与链路状态。
type InterfaceInfo struct {
	Name      string
	MAC       string
	MTU       int
	Up        bool
	Wireless  bool
	Addresses []string
}

/*
Interfaces 枚举当前设备的所有网络接口。
该函数只使用标准库与 /sys 只读探测，不调用 ip、ifconfig 等外部命令。

参数:
  - 无。

返回:
  - []InterfaceInfo: 按接口名升序排列的接口信息。
  - error: 读取接口列表失败时返回错误。
*/
func Interfaces() ([]InterfaceInfo, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("读取网络接口失败: %w", err)
	}

	result := make([]InterfaceInfo, 0, len(interfaces))
	for _, iface := range interfaces {
		addresses := make([]string, 0, 2)
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				addresses = append(addresses, addr.String())
			}
		}

		result = append(result, InterfaceInfo{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			MTU:       iface.MTU,
			Up:        iface.Flags&net.FlagUp != 0,
			Wireless:  isWireless(iface.Name),
			Addresses: addresses,
		})
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result, nil
}

/*
WirelessInterfaces 只返回无线网络接口。
在非 Root Termux 环境中，该函数仅做被动识别，不触发任何无线扫描。

参数:
  - 无。

返回:
  - []InterfaceInfo: 无线接口列表；没有无线接口时返回空切片。
  - error: 读取接口列表失败时返回错误。
*/
func WirelessInterfaces() ([]InterfaceInfo, error) {
	interfaces, err := Interfaces()
	if err != nil {
		return nil, err
	}

	wireless := make([]InterfaceInfo, 0, len(interfaces))
	for _, iface := range interfaces {
		if iface.Wireless {
			wireless = append(wireless, iface)
		}
	}
	return wireless, nil
}

/*
LocalCIDR 推断当前设备最可能使用的局域网 /24 网段。
优先选择带 /sys/class/net/<name>/wireless 标记的接口，
找不到无线接口时回落到第一个非回环、非链路本地 IPv4 接口。

参数:
  - 无。

返回:
  - string: 形如 "192.168.1.0/24" 的网段。
  - error: 没有可用的 IPv4 局域网地址时返回错误。
*/
func LocalCIDR() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("读取网络接口失败: %w", err)
	}

	bestScore := 100
	bestCIDR := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		score := interfaceScore(iface.Name)
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}

			network := ip4.Mask(net.CIDRMask(24, 32))
			cidr := fmt.Sprintf("%s/24", network.String())
			if score == 0 {
				return cidr, nil
			}
			if score < bestScore {
				bestScore = score
				bestCIDR = cidr
			}
		}
	}

	if bestCIDR != "" {
		return bestCIDR, nil
	}
	return "", fmt.Errorf("未找到可用的 IPv4 局域网地址")
}

/*
interfaceScore 为候选网络接口计算优先级，数值越小越优先。
无线接口优先，其次是 wlan/eth/en 命名接口；
bridge、utun、docker 等虚拟或隧道接口会被显著降权。

参数:
  - name (string): 网络接口名称。

返回:
  - int: 优先级分数，0 表示无线接口。
*/
func interfaceScore(name string) int {
	switch {
	case isWireless(name):
		return 0
	case strings.HasPrefix(name, "wlan"), strings.HasPrefix(name, "wlp"):
		return 1
	case strings.HasPrefix(name, "eth"):
		return 2
	case strings.HasPrefix(name, "en"):
		return 3
	case strings.HasPrefix(name, "bridge"),
		strings.HasPrefix(name, "utun"),
		strings.HasPrefix(name, "gif"),
		strings.HasPrefix(name, "stf"),
		strings.HasPrefix(name, "awdl"),
		strings.HasPrefix(name, "llw"),
		strings.HasPrefix(name, "anpi"),
		strings.HasPrefix(name, "ap"),
		strings.HasPrefix(name, "tun"),
		strings.HasPrefix(name, "tap"),
		strings.HasPrefix(name, "docker"),
		strings.HasPrefix(name, "veth"),
		strings.HasPrefix(name, "vmnet"),
		strings.HasPrefix(name, "dummy"):
		return 90
	default:
		return 10
	}
}

/*
isWireless 通过 /sys/class/net/<name>/wireless 判断接口是否为无线接口。
该路径只存在于 Linux；在 macOS 等系统上会安全地返回 false。

参数:
  - name (string): 网络接口名称。

返回:
  - bool: 接口存在无线 sysfs 标记时返回 true。
*/
func isWireless(name string) bool {
	_, err := os.Stat("/sys/class/net/" + name + "/wireless")
	return err == nil
}
