// web 包提供纯 Go 的 Web 安全侦察能力，不发送攻击载荷。
package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// HeaderFinding 描述一项 HTTP 安全响应头的检查结果。
type HeaderFinding struct {
	Name     string
	Present  bool
	Value    string
	Severity string
	Advice   string
}

// CookieFinding 描述一条 Set-Cookie 的安全属性。
type CookieFinding struct {
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

// HeaderReport 汇总一次 HTTP 安全头审计的结果。
type HeaderReport struct {
	URL        string
	FinalURL   string
	StatusCode int
	Server     string
	PoweredBy  string
	Findings   []HeaderFinding
	Cookies    []CookieFinding
}

/*
AuditHeaders 对目标 URL 发起一次只读 GET 请求，并审计常见安全响应头。
该函数不会发送漏洞利用载荷，仅检查响应头、状态码与 Cookie 属性。

参数:
  - ctx (context.Context): 全局上下文，用于取消请求。
  - rawURL (string): 目标 URL，必须包含 http:// 或 https://。
  - timeout (time.Duration): 单次 HTTP 请求的总超时。

返回:
  - HeaderReport: 安全头与 Cookie 审计结果。
  - error: URL 非法、请求失败或响应读取失败时返回错误。
*/
func AuditHeaders(ctx context.Context, rawURL string, timeout time.Duration) (HeaderReport, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return HeaderReport{}, fmt.Errorf("URL 解析失败: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return HeaderReport{}, fmt.Errorf("仅支持 http:// 或 https:// URL")
	}
	if parsed.Host == "" {
		return HeaderReport{}, fmt.Errorf("URL 缺少主机名")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return HeaderReport{}, fmt.Errorf("创建请求失败: %w", err)
	}
	request.Header.Set("User-Agent", "NezhaCLI/0.3 (+https://github.com/ctkqiang)")

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("重定向次数过多")
			}
			return nil
		},
	}

	response, err := client.Do(request)
	if err != nil {
		return HeaderReport{}, fmt.Errorf("请求失败: %w", err)
	}
	defer response.Body.Close()

	report := HeaderReport{
		URL:        parsed.String(),
		FinalURL:   response.Request.URL.String(),
		StatusCode: response.StatusCode,
		Server:     response.Header.Get("Server"),
		PoweredBy:  response.Header.Get("X-Powered-By"),
	}

	checks := []struct {
		name     string
		severity string
		advice   string
	}{
		{"Strict-Transport-Security", "高", "HTTPS 站点应启用 HSTS，防止协议降级攻击"},
		{"Content-Security-Policy", "高", "使用 CSP 限制脚本来源，降低 XSS 风险"},
		{"X-Frame-Options", "中", "防止点击劫持，也可使用 CSP frame-ancestors"},
		{"X-Content-Type-Options", "中", "设置为 nosniff，阻止浏览器进行 MIME 类型嗅探"},
		{"Referrer-Policy", "低", "限制 Referer 泄漏敏感路径"},
		{"Permissions-Policy", "低", "限制摄像头、麦克风、定位等浏览器能力"},
		{"Cross-Origin-Opener-Policy", "低", "隔离跨源窗口，降低侧信道风险"},
		{"Cross-Origin-Resource-Policy", "低", "限制跨源资源嵌入"},
	}

	for _, check := range checks {
		value := response.Header.Get(check.name)
		severity := check.severity
		advice := check.advice

		if check.name == "Strict-Transport-Security" && parsed.Scheme != "https" {
			severity = "提示"
			advice = "HSTS 仅对 HTTPS 生效；建议先启用 HTTPS"
		}
		if check.name == "X-Frame-Options" && response.Header.Get("Content-Security-Policy") != "" {
			advice = "已存在 CSP；可同时检查 frame-ancestors 指令"
		}

		report.Findings = append(report.Findings, HeaderFinding{
			Name:     check.name,
			Present:  strings.TrimSpace(value) != "",
			Value:    strings.TrimSpace(value),
			Severity: severity,
			Advice:   advice,
		})
	}

	if report.Server != "" {
		report.Findings = append(report.Findings, HeaderFinding{
			Name:     "Server",
			Present:  true,
			Value:    report.Server,
			Severity: "信息",
			Advice:   "避免暴露精确的服务器版本",
		})
	}
	if report.PoweredBy != "" {
		report.Findings = append(report.Findings, HeaderFinding{
			Name:     "X-Powered-By",
			Present:  true,
			Value:    report.PoweredBy,
			Severity: "信息",
			Advice:   "避免暴露应用框架与版本",
		})
	}

	for _, cookie := range response.Cookies() {
		report.Cookies = append(report.Cookies, CookieFinding{
			Name:     cookie.Name,
			Secure:   cookie.Secure,
			HTTPOnly: cookie.HttpOnly,
			SameSite: sameSiteName(cookie.SameSite),
		})
	}

	return report, nil
}

/*
sameSiteName 将 http.SameSite 枚举转换为可读字符串。

参数:
  - mode (http.SameSite): Cookie 的 SameSite 模式。

返回:
  - string: 可读的 SameSite 名称。
*/
func sameSiteName(mode http.SameSite) string {
	switch mode {
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteNoneMode:
		return "None"
	default:
		return "未设置"
	}
}
