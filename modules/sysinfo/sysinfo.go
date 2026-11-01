// sysinfo 模块汇总本机环境、网络接口与出站连通性。
package sysinfo

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/netutil"
	"github.com/ctkqiang/nezha_cli/pkg/system"
)

const (
	// DefaultTargets 是默认的出站连通性探测目标。
	DefaultTargets = "1.1.1.1:443,8.8.8.8:53"
)

// Module 是系统环境模块。
type Module struct{}

/*
New 创建系统环境模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回系统环境模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "sysinfo",
		Aliases:  []string{"sys", "env"},
		Category: modulekit.CategorySystem,
		Summary:  "本机环境、网络接口与出站连通性",
		Description: "汇总主机名、系统、架构、UID、Root 状态、发行版与内核版本，\n" +
			"枚举网络接口并执行 TCP 出站连通性探测。\n" +
			"全部通过标准库与只读文件完成，不调用 uname、ip 等外部命令。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("TARGETS", "出站连通性探测目标，host:port 逗号分隔", false, DefaultTargets),
			modulekit.Option("TIMEOUT", "单个目标连接超时", false, "3s"),
		},
	}
}

/*
Run 收集并输出本机环境信息。

参数:
  - ctx (context.Context): 探测上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 接口枚举失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	info := system.CollectInfo()

	root := "否"
	if info.Root {
		root = "是"
	}

	modulekit.Section(out, "本机环境")
	modulekit.KeyValues(out, [][2]string{
		{"主机名", info.Hostname},
		{"系统", info.OS},
		{"架构", info.Arch},
		{"Go 版本", info.GoVersion},
		{"UID", strconv.Itoa(info.UID)},
		{"Root", root},
		{"发行版", info.Distro},
		{"内核", info.Kernel},
	}, 64)

	interfaces, err := system.Interfaces()
	if err != nil {
		return err
	}
	interfaceRows := make([][]string, 0, len(interfaces))
	for _, iface := range interfaces {
		state := "down"
		if iface.Up {
			state = "up"
		}
		interfaceRows = append(interfaceRows, []string{
			iface.Name,
			dash(iface.MAC),
			state,
			yesNo(iface.Wireless),
			modulekit.Etc(strings.Join(iface.Addresses, ", "), 48),
		})
	}
	modulekit.Section(out, fmt.Sprintf("网络接口 %d", len(interfaceRows)))
	modulekit.Table(out, []string{"接口", "MAC", "状态", "无线", "地址"}, interfaceRows, 46)

	targets := netutil.SplitTargets(options.String("TARGETS", DefaultTargets))
	timeout := options.Duration("TIMEOUT", 3*time.Second)
	if len(targets) > 0 {
		results := system.CheckConnectivity(ctx, targets, timeout)
		connectivityRows := make([][]string, 0, len(results))
		for _, result := range results {
			status := "失败"
			latency := "-"
			detail := result.Error
			if result.OK {
				status = "连通"
				latency = result.Latency.Round(time.Millisecond).String()
				detail = "-"
			}
			connectivityRows = append(connectivityRows, []string{
				result.Target,
				status,
				latency,
				modulekit.Etc(detail, 44),
			})
		}
		modulekit.Section(out, "出站连通性")
		modulekit.Table(out, []string{"目标", "状态", "延迟", "错误"}, connectivityRows, 44)
	}

	return nil
}

/*
dash 在值为空时返回占位符。

参数:
  - value (string): 原始值。

返回:
  - string: 原值或 “-”。
*/
func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

/*
yesNo 把布尔值转换为中文状态。

参数:
  - value (bool): 布尔值。

返回:
  - string: “是”或“否”。
*/
func yesNo(value bool) string {
	if value {
		return "是"
	}
	return "否"
}
