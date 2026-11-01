// bt 模块被动枚举本机蓝牙适配器，不发起扫描、配对或连接。
package bt

import (
	"context"
	"fmt"
	"io"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
	"github.com/ctkqiang/nezha_cli/pkg/system"
)

// Module 是蓝牙适配器枚举模块。
type Module struct{}

/*
New 创建蓝牙适配器枚举模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回蓝牙适配器枚举模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "bt",
		Aliases:  []string{"bluetooth", "hci"},
		Category: modulekit.CategoryBluetooth,
		Summary:  "本机蓝牙适配器被动枚举",
		Description: "读取 sysfs 被动枚举本机 HCI 蓝牙适配器的名称、地址与路径。\n" +
			"适用于授权评估前确认主机是否存在可用的蓝牙攻击面。\n" +
			"只做被动枚举，不发起扫描、配对或连接；\n" +
			"非 Root 的 Android/Termux 通常无法访问蓝牙 sysfs，这属于系统权限边界而非模块故障。\n" +
			"枚举结果可作为后续蓝牙评估工具选型与攻击面分析的依据。",
		Usage: "use bt\n" +
			"set SYSFS /sys/class/bluetooth\n" +
			"run",
		Author: modulekit.Author,
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://docs.kernel.org/",
			"https://github.com/termux/termux-app",
		},
		Options: []model.Option{
			modulekit.Option("SYSFS", "蓝牙 sysfs 根目录；默认 /sys/class/bluetooth，只做只读枚举", false, "/sys/class/bluetooth"),
		},
	}
}

/*
Run 枚举蓝牙适配器并输出结果。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 始终返回 nil；无法访问 sysfs 时以说明文本呈现。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	_ = ctx
	sysfs := options.String("SYSFS", "/sys/class/bluetooth")

	adapters, err := system.BluetoothAdapters()
	if err != nil {
		modulekit.Section(out, "蓝牙")
		fmt.Fprintf(out, "无法访问 %s：%v\n", sysfs, err)
		fmt.Fprintln(out, "非 Root 的 Android/Termux 通常不暴露蓝牙 HCI sysfs；这是系统权限限制。")
		fmt.Fprintln(out, "如需评估 BLE 设备，请使用具备相应权限的测试主机或专用硬件。")
		logger.Warn("蓝牙适配器不可用：%v", err)
		return nil
	}

	rows := make([][]string, 0, len(adapters))
	for _, adapter := range adapters {
		rows = append(rows, []string{adapter.Name, adapter.Address, adapter.Path})
	}

	modulekit.Section(out, fmt.Sprintf("蓝牙适配器 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未发现蓝牙适配器。")
		return nil
	}
	modulekit.Table(out, []string{"名称", "地址", "路径"}, rows, 56)
	logger.Info("蓝牙枚举完成：%d 个适配器", len(rows))
	return nil
}
