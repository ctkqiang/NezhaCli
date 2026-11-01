// wifi_scan 模块通过 ESP 协处理器扫描周边接入点。
package wifi_scan

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strconv"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/wireless/esp"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Module 是 WiFi 扫描模块。
type Module struct{}

/*
New 创建 WiFi 扫描模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 WiFi 扫描模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "wifi_scan",
		Aliases:  []string{"wscan", "ap_scan"},
		Category: modulekit.CategoryWireless,
		Summary:  "ESP 协处理器扫描周边接入点",
		Description: "通过 ESP8266/ESP32 协处理器主动扫描周边接入点，返回 SSID、BSSID、信道与 RSSI。\n" +
			"适用于授权评估前定位目标 AP 的信道与信号，为去认证与关联测试做准备。\n" +
			"宿主机只访问串口，不需要 Root、raw socket 或 monitor 模式；\n" +
			"ESP32-C5 等双频固件可同时返回 5GHz 结果。\n" +
			"扫描得到的 BSSID 与信道可直接交给 wifi_deauth 使用。",
		Usage: "use wifi_scan\n" +
			"set MIN_RSSI -70\n" +
			"set SORT rssi\n" +
			"run",
		Author: modulekit.Author,
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://docs.espressif.com/projects/esp-at/en/latest/",
			"https://en.wikipedia.org/wiki/IEEE_802.11",
		},
		Options: []model.Option{
			modulekit.Option("PORT", "串口设备路径；留空时自动探测", false, ""),
			modulekit.Option("SORT", "排序方式；取值 rssi/channel/ssid，其余按 rssi 降序", false, "rssi"),
			modulekit.Option("MIN_RSSI", "最低信号阈值；低于该值的接入点被过滤，通常为负数", false, "-100"),
			modulekit.Option("HIDDEN", "是否显示隐藏 SSID；false 时过滤无名称的接入点", false, "true"),
		},
	}
}

/*
Run 打开协处理器、执行扫描并输出接入点列表。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 串口握手失败、扫描失败或参数非法时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx
	injector, err := esp.Open(options.Get("PORT"))
	if err != nil {
		return err
	}
	defer injector.Close()

	networks, err := injector.Scan()
	if err != nil {
		return err
	}

	minRSSI := options.Int("MIN_RSSI", -100)
	showHidden := options.Bool("HIDDEN", true)

	filtered := make([]esp.Network, 0, len(networks))
	for _, network := range networks {
		if network.RSSI < minRSSI {
			continue
		}
		if network.SSID == "" && !showHidden {
			continue
		}
		filtered = append(filtered, network)
	}

	sortNetworks(filtered, options.String("SORT", "rssi"))

	modulekit.Section(out, "扫描参数")
	modulekit.KeyValues(out, [][2]string{
		{"串口", injector.PortName()},
		{"固件", fmt.Sprintf("v%d", injector.FirmwareVersion())},
		{"原始结果", strconv.Itoa(len(networks))},
		{"过滤后", strconv.Itoa(len(filtered))},
		{"最低 RSSI", strconv.Itoa(minRSSI)},
	}, 60)

	rows := make([][]string, 0, len(filtered))
	for _, network := range filtered {
		ssid := network.SSID
		if ssid == "" {
			ssid = "<隐藏>"
		}
		rows = append(rows, []string{
			modulekit.Etc(ssid, 32),
			network.BSSID,
			strconv.Itoa(network.Channel),
			strconv.Itoa(network.RSSI),
			signalBars(network.RSSI),
		})
	}

	modulekit.Section(out, fmt.Sprintf("接入点 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未扫描到接入点。请确认天线、供电与固件扫描能力。")
		return nil
	}
	modulekit.Table(out, []string{"SSID", "BSSID", "信道", "RSSI", "信号"}, rows, 34)
	logger.Info("WiFi 扫描完成：%d 个接入点", len(rows))
	return nil
}

/*
sortNetworks 按指定字段排序接入点。

参数:
  - networks ([]esp.Network): 接入点列表。
  - mode (string): rssi、channel 或 ssid。

返回:
  - 无；原地排序。
*/
func sortNetworks(networks []esp.Network, mode string) {
	switch mode {
	case "channel":
		sort.Slice(networks, func(left int, right int) bool {
			if networks[left].Channel == networks[right].Channel {
				return networks[left].RSSI > networks[right].RSSI
			}
			return networks[left].Channel < networks[right].Channel
		})
	case "ssid":
		sort.Slice(networks, func(left int, right int) bool {
			return networks[left].SSID < networks[right].SSID
		})
	default:
		sort.Slice(networks, func(left int, right int) bool {
			return networks[left].RSSI > networks[right].RSSI
		})
	}
}

/*
signalBars 把 RSSI 转换为五档信号条。

参数:
  - rssi (int): 信号强度。

返回:
  - string: 信号条文本。
*/
func signalBars(rssi int) string {
	switch {
	case rssi >= -50:
		return "▂▄▆█"
	case rssi >= -65:
		return "▂▄▆"
	case rssi >= -75:
		return "▂▄"
	default:
		return "▂"
	}
}
