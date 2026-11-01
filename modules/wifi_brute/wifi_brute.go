// wifi_brute 模块通过 ESP 协处理器对目标 SSID 执行在线密码字典尝试。
package wifi_brute

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/wireless/esp"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// maxConsecutiveErrors 是连续协处理器错误上限，超过后中止，避免无意义重试。
	maxConsecutiveErrors = 5

	// maxPasswordBytes 是 WPA2 密码的协议上限。
	maxPasswordBytes = 63
)

// Module 是在线 WiFi 密码尝试模块。
type Module struct{}

/*
New 创建在线 WiFi 密码尝试模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回在线 WiFi 密码尝试模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "wifi_brute",
		Aliases:  []string{"wbrute", "assoc"},
		Category: modulekit.CategoryWireless,
		Summary:  "ESP 协处理器在线 WiFi 密码字典尝试",
		Description: "读取密码字典，逐条调用 ESP 固件关联目标 SSID，命中后立即停止。\n" +
			"适用于对已获书面授权的目标做弱口令验证与小规模字典测试。\n" +
			"影响等级高：会尝试关联目标 AP；固件每次关联最长阻塞约 12 秒，\n" +
			"高频尝试可能触发 AP 的锁定与告警，禁止对未授权网络使用。\n" +
			"字典可由 crunch 生成，目标 SSID 与信道可先用 wifi_scan 确认。",
		Usage: "use wifi_brute\n" +
			"set SSID NezhaLab\n" +
			"set WORDLIST /sdcard/dict.txt\n" +
			"set DELAY 500ms\n" +
			"run",
		Author: modulekit.Author,
		Impact: "高（会尝试关联目标 AP）",
		Options: []model.Option{
			modulekit.Option("PORT", "串口设备路径；留空时自动探测", false, ""),
			modulekit.Option("SSID", "目标 SSID；长度 1-32 字节，超限报错", true, ""),
			modulekit.Option("WORDLIST", "密码字典路径；每行一个密码，超 63 字节自动跳过", true, ""),
			modulekit.Option("DELAY", "两次尝试之间的额外延迟；不能为负数", false, "200ms"),
			modulekit.Option("MAX", "最大尝试次数；0 表示不限制，负数报错", false, "0"),
			modulekit.Option("STOP_ON_SUCCESS", "命中后是否立即停止；true 或 false", false, "true"),
		},
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://docs.espressif.com/projects/esp-at/en/latest/",
			"https://en.wikipedia.org/wiki/IEEE_802.11",
		},
	}
}

/*
Run 打开字典与协处理器，逐条尝试密码。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法、字典读取失败、协处理器连续失败或执行被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	ssid := options.Get("SSID")
	if err := esp.ValidateSSID(ssid); err != nil {
		return err
	}

	wordlistPath := strings.TrimSpace(options.Get("WORDLIST"))
	if wordlistPath == "" {
		return fmt.Errorf("WORDLIST 不能为空")
	}
	file, err := os.Open(wordlistPath)
	if err != nil {
		return fmt.Errorf("打开字典 %s 失败: %w", wordlistPath, err)
	}
	defer file.Close()

	maxAttempts := options.Int("MAX", 0)
	if maxAttempts < 0 {
		return fmt.Errorf("MAX 不能为负数")
	}
	delay := options.Duration("DELAY", 200*time.Millisecond)
	if delay < 0 {
		return fmt.Errorf("DELAY 不能为负数")
	}
	stopOnSuccess := options.Bool("STOP_ON_SUCCESS", true)

	injector, err := esp.Open(options.Get("PORT"))
	if err != nil {
		return err
	}
	defer injector.Close()

	modulekit.Section(out, "尝试配置")
	maxText := "不限制"
	if maxAttempts > 0 {
		maxText = fmt.Sprintf("%d", maxAttempts)
	}
	modulekit.KeyValues(out, [][2]string{
		{"串口", injector.PortName()},
		{"SSID", ssid},
		{"字典", wordlistPath},
		{"最大次数", maxText},
		{"额外延迟", delay.String()},
		{"命中即停", fmt.Sprintf("%t", stopOnSuccess)},
	}, 64)

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	started := time.Now()
	attempts := 0
	skipped := 0
	consecutiveErrors := 0

	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}

		password := strings.TrimRight(scanner.Text(), "\r")
		if password == "" {
			continue
		}
		if len([]byte(password)) > maxPasswordBytes {
			skipped++
			continue
		}
		if maxAttempts > 0 && attempts >= maxAttempts {
			break
		}

		attempts++
		success, err := injector.Associate(ssid, password)
		if err != nil {
			consecutiveErrors++
			logger.Warn("第 %d 次尝试出错：%v", attempts, err)
			if consecutiveErrors >= maxConsecutiveErrors {
				return fmt.Errorf("连续 %d 次协处理器错误，中止尝试", consecutiveErrors)
			}
		} else {
			consecutiveErrors = 0
			if success {
				modulekit.Section(out, "命中")
				modulekit.KeyValues(out, [][2]string{
					{"SSID", ssid},
					{"密码", password},
					{"尝试次数", fmt.Sprintf("%d", attempts)},
					{"耗时", time.Since(started).Round(time.Second).String()},
				}, 60)
				logger.Success("WiFi 密码命中：%s / %s", ssid, password)
				if stopOnSuccess {
					return nil
				}
			}
		}

		if attempts%10 == 0 {
			logger.Info("已尝试 %d 次，用时 %s", attempts, time.Since(started).Round(time.Second))
		}

		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("读取字典失败: %w", err)
	}

	modulekit.Section(out, "结果")
	modulekit.KeyValues(out, [][2]string{
		{"尝试次数", fmt.Sprintf("%d", attempts)},
		{"跳过超长", fmt.Sprintf("%d", skipped)},
		{"耗时", time.Since(started).Round(time.Second).String()},
		{"结果", "字典耗尽，未命中"},
	}, 60)
	logger.Warn("字典耗尽，未找到可用密码：%s", ssid)
	return nil
}
