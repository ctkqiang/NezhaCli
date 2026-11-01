// wifi_list 模块展示本机无线接口状态，并可选通过 ESP 协处理器扫描周边网络。
package wifi_list

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/wireless/esp"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	"github.com/ctkqiang/nezha_cli/pkg/system"
)

const (
	// wpaSupplicantPath 是 Linux 无线状态文件；Android 上通常不可读。
	wpaSupplicantPath = "/proc/net/wireless"
)

// procWireless 描述 /proc/net/wireless 中的一行接口状态。
type procWireless struct {
	name    string
	status  string
	quality string
	level   string
}

// Module 是无线接口与周边网络列表模块。
type Module struct{}

/*
New 创建无线列表模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回无线列表模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "wifi_list",
		Aliases:  []string{"wlist", "wifi"},
		Category: modulekit.CategoryWireless,
		Summary:  "本机无线接口状态与周边接入点",
		Description: "列出本机无线接口、链路状态与 /proc/net/wireless 中的信号质量。\n" +
			"适用于快速查看宿主机无线栈状态，或借助 ESP 查看周边接入点。\n" +
			"纯 Go 读取系统接口，无 Root 要求；非 Root 的 Android 会限制读取无线状态，\n" +
			"此时请设置 ESP=true 走协处理器扫描路径。\n" +
			"与 esp 模块共享串口链路，可与 wifi_scan 交叉验证扫描结果。",
		Usage: "use wifi_list\n" +
			"set ESP true\n" +
			"run",
		Author: modulekit.Author,
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://docs.espressif.com/projects/esp-at/en/latest/",
			"https://en.wikipedia.org/wiki/IEEE_802.11",
		},
		Options: []model.Option{
			modulekit.Option("ESP", "是否通过 ESP 协处理器执行扫描；true 或 false", false, "false"),
			modulekit.Option("PORT", "串口设备路径；留空自动探测，非空也会触发 ESP 扫描", false, ""),
		},
	}
}

/*
Run 输出无线接口与可选的扫描结果。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: ESP 握手或扫描失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx
	printInterfaces(out, options)

	if options.Bool("ESP", false) || strings.TrimSpace(options.Get("PORT")) != "" {
		return scanWithESP(out, options)
	}

	fmt.Fprintln(out, "提示：未启用 ESP 时只展示本机接口，不进行主动扫描。")
	fmt.Fprintln(out, "      设置 ESP=true 并连接 ESP8266/ESP32 协处理器后，可执行真实扫描。")
	return nil
}

/*
printInterfaces 输出本机无线接口与 /proc/net/wireless 状态。

参数:
  - out (io.Writer): 结果输出目标。
  - options (model.Options): 模块参数。

返回:
  - 无。
*/
func printInterfaces(out io.Writer, options model.Options) {
	_ = options
	interfaces, err := system.Interfaces()
	if err != nil {
		modulekit.Section(out, "无线接口")
		fmt.Fprintf(out, "读取网络接口失败：%v\n", err)
		return
	}

	procEntries := readProcWireless()
	rows := make([][]string, 0, len(interfaces))
	for _, iface := range interfaces {
		if !isWirelessInterface(iface.Name, iface.Wireless) {
			continue
		}
		state := "down"
		if iface.Up {
			state = "up"
		}
		quality := "-"
		level := "-"
		if entry, ok := procEntries[iface.Name]; ok {
			quality = entry.quality
			level = entry.level
		}
		rows = append(rows, []string{
			iface.Name,
			state,
			modulekit.Etc(strings.Join(iface.Addresses, ", "), 40),
			quality,
			level,
		})
	}

	modulekit.Section(out, fmt.Sprintf("无线接口 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未发现无线接口。Android 非 Root 环境可能隐藏 wlan 状态，请使用 ESP 路径。")
		return
	}
	modulekit.Table(out, []string{"接口", "状态", "地址", "质量", "信号"}, rows, 42)
}

/*
scanWithESP 通过协处理器扫描周边接入点。

参数:
  - out (io.Writer): 结果输出目标。
  - options (model.Options): 模块参数。

返回:
  - error: 串口握手或扫描失败时返回错误。
*/
func scanWithESP(out io.Writer, options model.Options) error {
	injector, err := esp.Open(options.Get("PORT"))
	if err != nil {
		return err
	}
	defer injector.Close()

	networks, err := injector.Scan()
	if err != nil {
		return err
	}

	rows := make([][]string, 0, len(networks))
	for _, network := range networks {
		ssid := network.SSID
		if ssid == "" {
			ssid = "<隐藏>"
		}
		rows = append(rows, []string{
			modulekit.Etc(ssid, 32),
			network.BSSID,
			fmt.Sprintf("%d", network.Channel),
			fmt.Sprintf("%d", network.RSSI),
		})
	}

	modulekit.Section(out, fmt.Sprintf("ESP 扫描结果 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "协处理器未返回接入点。")
	} else {
		modulekit.Table(out, []string{"SSID", "BSSID", "信道", "RSSI"}, rows, 36)
	}
	logger.Info("ESP 扫描完成：%d 个接入点", len(rows))
	return nil
}

/*
readProcWireless 解析 /proc/net/wireless；文件不存在或不可读时返回空映射。

参数:
  - 无。

返回:
  - map[string]procWireless: 接口名到状态行的映射。
*/
func readProcWireless() map[string]procWireless {
	entries := make(map[string]procWireless, 4)
	data, err := os.ReadFile(wpaSupplicantPath)
	if err != nil {
		return entries
	}

	for index, line := range strings.Split(string(data), "\n") {
		if index < 2 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ":")
		entries[name] = procWireless{
			name:    name,
			status:  cleanNumber(fields[1]),
			quality: cleanNumber(fields[2]),
			level:   cleanNumber(fields[3]),
		}
	}
	return entries
}

/*
cleanNumber 去掉 /proc/net/wireless 数值末尾的点号。

参数:
  - value (string): 原始字段。

返回:
  - string: 清理后的字段。
*/
func cleanNumber(value string) string {
	return strings.TrimSuffix(value, ".")
}

/*
isWirelessInterface 判断接口是否应视为无线接口。

参数:
  - name (string): 接口名。
  - detected (bool): 系统探测结果。

返回:
  - bool: 无线接口返回 true。
*/
func isWirelessInterface(name string, detected bool) bool {
	if detected {
		return true
	}
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "wlan") || strings.HasPrefix(lower, "wifi") || strings.HasPrefix(lower, "wl")
}
