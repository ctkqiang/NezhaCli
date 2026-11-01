// http 模块提供原始 HTTP 请求构造与回显，用于战场 Web 排障。
package http

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/config"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// maxBodyBytes 是响应体读取上限。
	maxBodyBytes = 1 << 20
)

// Module 是原始 HTTP 请求模块。
type Module struct{}

/*
New 创建原始 HTTP 请求模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回原始 HTTP 请求模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "http",
		Aliases:  []string{"curl", "request"},
		Category: modulekit.CategoryWeb,
		Summary:  "原始 HTTP 请求构造与回显",
		Description: "构造任意方法与请求头的单次 HTTP 请求，回显状态行、响应头与响应体。\n" +
			"适用于验证绕过效果、接口调试与观察 WAF 拦截行为等战场排障场景。\n" +
			"纯 Go 实现、无外部依赖；响应体读取上限 1MB、预览上限 2048 字符；\n" +
			"HEADERS 用分号分隔 k:v 对，BODY 为内联文本，BODYFILE 提供请求体文件且优先于 BODY。",
		Usage:  "use http\nset URL https://example.com/api\nset METHOD POST\nset HEADERS Content-Type:application/json;X-Test:1\nset BODY {\"a\":1}\nrun",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("URL", "目标 URL，必须以 http:// 或 https:// 开头；不自动补全协议", true, ""),
			modulekit.Option("METHOD", "HTTP 方法，自动转为大写；不校验合法性", false, "GET"),
			modulekit.Option("HEADERS", "附加请求头，k:v 用分号分隔；无法解析的项被忽略并告警", false, ""),
			modulekit.Option("BODY", "内联请求体文本；与 BODYFILE 同时设置时以文件优先", false, ""),
			modulekit.Option("BODYFILE", "请求体文件路径；文件打不开直接报错；优先于 BODY", false, ""),
			modulekit.Option("TIMEOUT", "单次请求超时；格式如 10s；超时直接报错", false, "10s"),
			modulekit.Option("SHOW_BODY", "是否回显响应体，支持 true/false；关闭可减少输出", false, "true"),
		},
		References: []string{
			"https://github.com/ctkqiang/NezhaCli",
			"https://www.rfc-editor.org/rfc/rfc9110",
		},
	}
}

/*
Run 构造并发送请求，回显状态、响应头与响应体。

参数:
  - ctx (context.Context): 请求上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 目标非法或请求失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	target := strings.TrimSpace(options.Get("URL"))
	if target == "" || !strings.HasPrefix(target, "http") {
		return fmt.Errorf("URL 必须以 http:// 或 https:// 开头")
	}

	method := strings.ToUpper(strings.TrimSpace(options.String("METHOD", "GET")))

	var bodyReader io.Reader
	bodyFile := strings.TrimSpace(options.Get("BODYFILE"))
	if bodyFile != "" {
		file, err := os.Open(bodyFile)
		if err != nil {
			return fmt.Errorf("打开请求体文件失败: %w", err)
		}
		defer file.Close()
		bodyReader = file
	} else if body := options.Get("BODY"); body != "" {
		bodyReader = strings.NewReader(body)
	}

	timeout := options.Duration("TIMEOUT", 10*time.Second)
	client := &http.Client{Timeout: timeout}

	request, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return fmt.Errorf("构造请求失败: %w", err)
	}
	request.Header.Set("User-Agent", "nezha/"+config.AppVersion)
	for _, pair := range strings.Split(options.Get("HEADERS"), ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, ":")
		if !ok {
			logger.Warn("忽略非法请求头: %s", pair)
			continue
		}
		request.Header.Set(strings.TrimSpace(key), strings.TrimSpace(value))
	}

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("请求失败: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return err
	}

	modulekit.Section(out, "响应")
	modulekit.KeyValues(out, [][2]string{
		{"状态", response.Status},
		{"协议", response.Proto},
		{"内容类型", response.Header.Get("Content-Type")},
		{"响应体字节", fmt.Sprintf("%d", len(body))},
	}, 60)

	modulekit.Section(out, "响应头")
	for key, values := range response.Header {
		fmt.Fprintf(out, "  %s: %s\n", key, strings.Join(values, "; "))
	}

	if options.Bool("SHOW_BODY", true) && len(body) > 0 {
		preview := string(body)
		if len(preview) > 2048 {
			preview = preview[:2048] + "…（已截断）"
		}
		modulekit.Section(out, "响应体")
		fmt.Fprintln(out, preview)
	}
	logger.Success("%s %s -> %s", method, target, response.Status)
	return nil
}
