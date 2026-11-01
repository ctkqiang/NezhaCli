// wifi_clone 模块通过 ESP 协处理器创建、查询与关闭同名克隆 AP。
package wifi_clone

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/wireless/esp"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// pollInterval 是克隆 AP 在线设备轮询间隔。
	pollInterval = 3 * time.Second
)

// Module 是克隆 AP 模块。
type Module struct{}

/*
New 创建克隆 AP 模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回克隆 AP 模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "wifi_clone",
		Aliases:  []string{"clone", "rogue_ap"},
		Category: modulekit.CategoryWireless,
		Summary:  "ESP 协处理器克隆 AP 与在线设备监控",
		Description: "让 ESP 固件以相同 SSID 与密码开启 SoftAP，并保留 STA 接口用于注入。\n" +
			"支持开启、关闭、查询在线设备以及定时监控；监控会差分出新接入与离开的 MAC。\n" +
			"这是高影响操作，仅可用于已获得书面授权的红队评估与无线健壮性测试。",
		Author: modulekit.Author,
		Impact: "高（会创建伪造接入点）",
		Options: []model.Option{
			modulekit.Option("PORT", "串口设备；留空自动探测", false, ""),
			modulekit.Option("ACTION", "动作：up / down / status / watch", false, "status"),
			modulekit.Option("SSID", "克隆 SSID；ACTION=up/watch 时必填", false, ""),
			modulekit.Option("PASSWORD", "克隆密码；留空表示开放网络", false, ""),
			modulekit.Option("CHANNEL", "克隆 AP 信道", false, "1"),
			modulekit.Option("WATCH", "监控时长，例如 60s；0 表示直到 Ctrl+C", false, "0s"),
			modulekit.Option("DOWN_ON_EXIT", "监控结束后是否关闭克隆 AP", false, "true"),
		},
		References: []string{"https://github.com/ctkqiang/wifisec"},
	}
}

/*
Run 根据 ACTION 开启、关闭、查询或监控克隆 AP。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法、协处理器失败或执行被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	action := strings.ToLower(options.String("ACTION", "status"))
	switch action {
	case "up", "down", "status", "watch":
	default:
		return fmt.Errorf("ACTION 只能是 up、down、status 或 watch")
	}

	ssid := options.Get("SSID")
	password := options.Get("PASSWORD")
	if action == "up" || action == "watch" {
		if err := esp.ValidateSSID(ssid); err != nil {
			return err
		}
		if err := esp.ValidatePassword(password); err != nil {
			return err
		}
	}

	channel := options.Int("CHANNEL", 1)
	if channel < 1 || channel > 196 {
		return fmt.Errorf("CHANNEL 超出范围: %d", channel)
	}

	injector, err := esp.Open(options.Get("PORT"))
	if err != nil {
		return err
	}
	defer injector.Close()

	modulekit.Section(out, "克隆配置")
	modulekit.KeyValues(out, [][2]string{
		{"串口", injector.PortName()},
		{"动作", action},
		{"SSID", dash(ssid)},
		{"信道", fmt.Sprintf("%d", channel)},
	}, 60)

	switch action {
	case "up":
		return bringUp(out, injector, ssid, password, channel)
	case "down":
		if err := injector.CloneAPDown(); err != nil {
			return err
		}
		fmt.Fprintln(out, "克隆 AP 已关闭。")
		logger.Info("克隆 AP 已关闭")
		return nil
	case "status":
		return printStatus(out, injector)
	default:
		return watch(ctx, out, injector, options, ssid, password, channel)
	}
}

/*
bringUp 开启克隆 AP 并输出其 MAC。

参数:
  - out (io.Writer): 结果输出目标。
  - injector (*esp.Injector): 已握手的协处理器。
  - ssid (string): 克隆 SSID。
  - password (string): 克隆密码。
  - channel (int): 克隆信道。

返回:
  - error: 固件拒绝开启时返回错误。
*/
func bringUp(out io.Writer, injector *esp.Injector, ssid string, password string, channel int) error {
	mac, err := injector.CloneAPUp(ssid, password, channel)
	if err != nil {
		return err
	}

	modulekit.Section(out, "克隆 AP")
	modulekit.KeyValues(out, [][2]string{
		{"SSID", ssid},
		{"信道", fmt.Sprintf("%d", channel)},
		{"BSSID", mac},
		{"密码", passwordMask(password)},
	}, 60)
	fmt.Fprintln(out, "克隆 AP 已开启；执行 ACTION=down 可关闭。")
	logger.Success("克隆 AP 已开启：%s · %s", ssid, mac)
	return nil
}

/*
watch 开启克隆 AP 并定时轮询在线设备，差分接入与离开事件。

参数:
  - ctx (context.Context): 执行上下文。
  - out (io.Writer): 结果输出目标。
  - injector (*esp.Injector): 已握手的协处理器。
  - options (model.Options): 模块参数。
  - ssid (string): 克隆 SSID。
  - password (string): 克隆密码。
  - channel (int): 克隆信道。

返回:
  - error: 开启失败、轮询失败或执行被取消时返回错误。
*/
func watch(ctx context.Context, out io.Writer, injector *esp.Injector, options model.Options, ssid string, password string, channel int) error {
	if err := bringUp(out, injector, ssid, password, channel); err != nil {
		return err
	}

	duration := options.Duration("WATCH", 0)
	downOnExit := options.Bool("DOWN_ON_EXIT", true)
	deadline := time.Time{}
	if duration > 0 {
		deadline = time.Now().Add(duration)
	}

	previous := make(map[string]struct{}, 8)
	if err := pollOnce(ctx, out, injector, previous, true); err != nil {
		return err
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if downOnExit {
				_ = injector.CloneAPDown()
			}
			return ctx.Err()
		case <-ticker.C:
			if !deadline.IsZero() && time.Now().After(deadline) {
				if downOnExit {
					if err := injector.CloneAPDown(); err != nil {
						logger.Warn("关闭克隆 AP 失败：%v", err)
						return err
					}
					fmt.Fprintln(out, "监控结束，克隆 AP 已关闭。")
				} else {
					fmt.Fprintln(out, "监控结束，克隆 AP 保持运行。")
				}
				return nil
			}
			if err := pollOnce(ctx, out, injector, previous, false); err != nil {
				if downOnExit {
					_ = injector.CloneAPDown()
				}
				return err
			}
		}
	}
}

/*
pollOnce 查询一次在线设备并输出差分事件。

参数:
  - ctx (context.Context): 执行上下文。
  - out (io.Writer): 结果输出目标。
  - injector (*esp.Injector): 已握手的协处理器。
  - previous (map[string]struct{}): 上一轮在线 MAC 集合。
  - initial (bool): 是否为首次查询。

返回:
  - error: 状态查询失败时返回错误。
*/
func pollOnce(ctx context.Context, out io.Writer, injector *esp.Injector, previous map[string]struct{}, initial bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	macs, err := injector.CloneStatus()
	if err != nil {
		return err
	}

	current := make(map[string]struct{}, len(macs))
	for _, mac := range macs {
		current[mac] = struct{}{}
	}

	joined := make([]string, 0, len(macs))
	left := make([]string, 0, len(previous))
	for mac := range current {
		if _, exists := previous[mac]; !exists {
			joined = append(joined, mac)
		}
	}
	for mac := range previous {
		if _, exists := current[mac]; !exists {
			left = append(left, mac)
		}
	}
	sort.Strings(joined)
	sort.Strings(left)

	title := fmt.Sprintf("在线设备 %d", len(macs))
	if initial {
		title = "初始在线设备"
	}
	modulekit.Section(out, title)
	fmt.Fprintf(out, "在线：%s\n", joinOrDash(macs))
	if !initial {
		fmt.Fprintf(out, "新接入：%s\n", joinOrDash(joined))
		fmt.Fprintf(out, "已离开：%s\n", joinOrDash(left))
	}

	for mac := range current {
		previous[mac] = struct{}{}
	}
	for mac := range previous {
		if _, exists := current[mac]; !exists {
			delete(previous, mac)
		}
	}
	return nil
}

/*
printStatus 输出当前克隆 AP 的在线设备。

参数:
  - out (io.Writer): 结果输出目标。
  - injector (*esp.Injector): 已握手的协处理器。

返回:
  - error: 状态查询失败时返回错误。
*/
func printStatus(out io.Writer, injector *esp.Injector) error {
	macs, err := injector.CloneStatus()
	if err != nil {
		return err
	}

	modulekit.Section(out, fmt.Sprintf("在线设备 %d", len(macs)))
	if len(macs) == 0 {
		fmt.Fprintln(out, "当前没有设备接入克隆 AP。")
		return nil
	}
	rows := make([][]string, 0, len(macs))
	for _, mac := range macs {
		rows = append(rows, []string{mac})
	}
	modulekit.Table(out, []string{"MAC"}, rows, 32)
	return nil
}

/*
passwordMask 对密码做展示脱敏。

参数:
  - password (string): 原始密码。

返回:
  - string: 脱敏后的占位文本。
*/
func passwordMask(password string) string {
	if strings.TrimSpace(password) == "" {
		return "开放网络"
	}
	return "********"
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
joinOrDash 把字符串切片连接为逗号分隔文本。

参数:
  - values ([]string): 原始切片。

返回:
  - string: 连接结果；空切片返回 “-”。
*/
func joinOrDash(values []string) string {
	if len(values) == 0 {
		return "-"
	}
	return strings.Join(values, ", ")
}
