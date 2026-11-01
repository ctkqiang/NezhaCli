// esp 模块检测 ESP8266/ESP32 协处理器链路、固件版本与射频能力。
package esp

import (
	"context"
	"fmt"
	"io"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/wireless/esp"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Module 是 ESP 协处理器诊断模块。
type Module struct{}

/*
New 创建 ESP 协处理器诊断模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 ESP 协处理器诊断模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "esp",
		Aliases:  []string{"wifi_esp", "serial"},
		Category: modulekit.CategoryWireless,
		Summary:  "ESP 协处理器握手、固件版本与射频能力",
		Description: "打开 USB 串口，执行 DTR/RTS 复位时序并完成 PING/PONG 握手。\n" +
			"输出固件协议版本、2.4/5GHz 能力与可选扫描结果，用于排错。\n" +
			"这是所有 WiFi 注入模块的前置检查：握手失败时不要继续执行主动操作。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("PORT", "串口设备；留空自动探测唯一 USB 串口", false, ""),
			modulekit.Option("SCAN", "握手后是否执行一次扫描", false, "false"),
		},
	}
}

/*
Run 打开协处理器并输出握手信息。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 串口打开、复位或握手失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx
	injector, err := esp.Open(options.Get("PORT"))
	if err != nil {
		return err
	}
	defer injector.Close()

	band := "2.4GHz"
	if injector.Supports5GHz() {
		band = "2.4GHz + 5GHz"
	}

	pairs := [][2]string{
		{"串口", injector.PortName()},
		{"固件协议", fmt.Sprintf("v%d", injector.FirmwareVersion())},
		{"射频能力", band},
		{"串口参数", fmt.Sprintf("%d 8N1", esp.BaudRate)},
	}
	if options.Bool("SCAN", false) {
		networks, err := injector.Scan()
		if err != nil {
			return err
		}
		pairs = append(pairs, [2]string{"扫描结果", fmt.Sprintf("%d 个接入点", len(networks))})
	}

	modulekit.Section(out, "ESP 协处理器")
	modulekit.KeyValues(out, pairs, 64)
	fmt.Fprintln(out, "握手成功：可以继续使用 wifi_scan / wifi_deauth / wifi_brute / wifi_clone。")
	logger.Info("ESP 协处理器就绪：%s，%s", injector.PortName(), band)
	return nil
}
