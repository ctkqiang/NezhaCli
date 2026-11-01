// system 包提供不依赖 Root 权限的本机环境与硬件侦察能力。
package system

import (
	"os"
	"runtime"
	"strings"
)

// Info 描述当前终端与操作系统的基础环境信息。
type Info struct {
	Hostname  string
	OS        string
	Arch      string
	GoVersion string
	UID       int
	Root      bool
	Distro    string
	Kernel    string
}

/*
CollectInfo 收集当前设备的基础环境信息。
该函数只读取标准库信息与 /etc、/proc 下的只读文件，不调用任何外部命令。

参数:
  - 无。

返回:
  - Info: 当前设备的环境信息快照。
*/
func CollectInfo() Info {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "未知"
	}

	uid := os.Getuid()
	return Info{
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		GoVersion: runtime.Version(),
		UID:       uid,
		Root:      uid == 0,
		Distro:    readDistro(),
		Kernel:    readKernel(),
	}
}

/*
readDistro 从 /etc/os-release 中提取可读的发行版名称。

参数:
  - 无。

返回:
  - string: 发行版名称；读取失败时返回“未知”。
*/
func readDistro() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "未知"
	}

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			name := strings.TrimPrefix(line, "PRETTY_NAME=")
			return strings.Trim(name, "\"")
		}
	}
	return "未知"
}

/*
readKernel 从 /proc/version 中读取内核版本字符串。

参数:
  - 无。

返回:
  - string: 内核版本信息；读取失败时返回“未知”。
*/
func readKernel() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "未知"
	}
	return strings.TrimSpace(string(data))
}
