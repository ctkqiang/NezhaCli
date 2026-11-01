// connect 模块提供一次性 TCP 原始交互，用于战场网络排障与协议验证。
package connect

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

// Module 是 TCP 原始连接模块。
type Module struct{}

/*
New 创建 TCP 原始连接模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 TCP 原始连接模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "connect",
		Aliases:  []string{"tcp", "nc", "socket"},
		Category: modulekit.CategoryRecon,
		Summary:  "一次性 TCP 原始交互",
		Description: "连接目标端口，可选发送文本或 hex 字节，读取并回显响应。\n" +
			"用于验证服务可达性、手工探测协议头与读取欢迎横幅，\n" +
			"替代需要额外安装的 nc；不进入交互模式，单次往返即退出。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("HOST", "目标主机或 IP", true, ""),
			modulekit.Option("PORT", "目标端口", true, ""),
			modulekit.Option("SEND", "待发送内容；HEX=true 时按 hex 字节解析", false, ""),
			modulekit.Option("HEX", "SEND 是否按 hex 解析（true/false）", false, "false"),
			modulekit.Option("TIMEOUT", "连接与读取总超时", false, "5s"),
			modulekit.Option("WAIT", "发送后的额外读取等待", false, "500ms"),
		},
	}
}

/*
Run 建立连接、可选发送数据并回显响应。

参数:
  - ctx (context.Context): 连接上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 参数非法或连接失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	host := strings.TrimSpace(options.Get("HOST"))
	port := options.Int("PORT", 0)
	if host == "" {
		return fmt.Errorf("HOST 不能为空")
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("PORT 非法: %d", port)
	}

	timeout := options.Duration("TIMEOUT", 5*time.Second)
	address := net.JoinHostPort(host, strconv.Itoa(port))

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("连接 %s 失败: %w", address, err)
	}
	defer conn.Close()

	modulekit.Section(out, "连接")
	modulekit.KeyValues(out, [][2]string{
		{"目标", address},
		{"本地", conn.LocalAddr().String()},
		{"远端", conn.RemoteAddr().String()},
	}, 60)

	sendRaw := options.Get("SEND")
	sent := 0
	if sendRaw != "" {
		var payload []byte
		if options.Bool("HEX", false) {
			payload, err = hex.DecodeString(strings.ReplaceAll(sendRaw, " ", ""))
			if err != nil {
				return fmt.Errorf("hex 解析失败: %w", err)
			}
		} else {
			payload = []byte(sendRaw)
		}
		if _, err := conn.Write(payload); err != nil {
			return fmt.Errorf("发送失败: %w", err)
		}
		sent = len(payload)
		logger.Info("已发送 %d 字节", sent)
	}

	deadline := time.Now().Add(timeout + options.Duration("WAIT", 500*time.Millisecond))
	_ = conn.SetReadDeadline(deadline)

	buffer := make([]byte, 4096)
	total := 0
	var builder strings.Builder
	for {
		count, readErr := conn.Read(buffer)
		if count > 0 {
			total += count
			builder.WriteString(hexPreview(buffer[:count]))
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			if netErr, ok := readErr.(net.Error); ok && netErr.Timeout() {
				break
			}
			return fmt.Errorf("读取失败: %w", readErr)
		}
		if total >= 64*1024 {
			break
		}
	}

	modulekit.Section(out, fmt.Sprintf("响应 %d 字节", total))
	if total == 0 {
		fmt.Fprintln(out, "（无响应）")
	} else {
		fmt.Fprintln(out, builder.String())
	}
	logger.Success("TCP 交互完成：发送 %d 字节，接收 %d 字节", sent, total)
	return nil
}

/*
hexPreview 把响应字节渲染为 hex + 文本双栏预览。

参数:
  - data ([]byte): 响应字节。

返回:
  - string: 预览文本。
*/
func hexPreview(data []byte) string {
	lines := make([]string, 0, len(data)/16+1)
	for offset := 0; offset < len(data); offset += 16 {
		end := offset + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]

		hexPart := hex.EncodeToString(chunk)
		for i := len(hexPart); i < 32; i += 2 {
			hexPart += "   "
		}

		var textPart strings.Builder
		for _, value := range chunk {
			if value >= 32 && value < 127 {
				textPart.WriteByte(value)
			} else {
				textPart.WriteByte('.')
			}
		}
		lines = append(lines, fmt.Sprintf("%04x  %s  |%s|", offset, hexPart, textPart.String()))
	}
	return strings.Join(lines, "\n")
}
