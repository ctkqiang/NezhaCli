// webfinger 模块移植自 QianKunQuan 项目：CMS/WAF/技术栈指纹识别。
package webfinger

import (
	"context"
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
	// maxBodyBytes 是响应体读取上限。
	maxBodyBytes = 1 << 20

	// defaultUserAgent 是默认请求头。
	defaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

// Module 是 Web 指纹识别模块。
type Module struct{}

/*
New 创建 Web 指纹识别模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 Web 指纹识别模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "webfinger",
		Aliases:  []string{"cms", "waf", "fingerprint"},
		Category: modulekit.CategoryWeb,
		Summary:  "CMS / WAF / 技术栈指纹识别",
		Description: "移植自作者的 QianKunQuan 项目：内置 21 款 CMS、14 款 WAF/CDN 指纹\n" +
			"与常见技术栈识别规则，一次请求输出 CMS 及版本、WAF 与技术栈结论。\n" +
			"只发只读 GET 请求，不做目录爆破（目录爆破请使用 webdir）。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("URL", "目标站点 URL，例如 https://example.com", true, ""),
			modulekit.Option("TIMEOUT", "单次请求超时", false, "10s"),
			modulekit.Option("UA", "自定义 User-Agent", false, ""),
		},
		References: []string{"https://github.com/ctkqiang/QianKunQuan"},
	}
}

/*
Run 获取首页并输出 CMS、WAF 与技术栈识别结论。

参数:
  - ctx (context.Context): 请求上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 目标非法或请求失败时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	target := strings.TrimRight(strings.TrimSpace(options.Get("URL")), "/")
	if target == "" || !strings.HasPrefix(target, "http") {
		return fmt.Errorf("URL 必须以 http:// 或 https:// 开头")
	}

	timeout := options.Duration("TIMEOUT", 10*time.Second)
	userAgent := options.String("UA", defaultUserAgent)
	client := &http.Client{Timeout: timeout}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "*/*")
	request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")

	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("请求首页失败: %w", err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	bodyText := string(body)

	modulekit.Section(out, "目标")
	modulekit.KeyValues(out, [][2]string{
		{"目标", target},
		{"状态码", fmt.Sprintf("%d", response.StatusCode)},
		{"Server", dash(response.Header.Get("Server"))},
	}, 60)

	cmsName, cmsVersion := detectCMS(response, bodyText)
	modulekit.Section(out, "CMS 识别")
	if cmsName == "" {
		fmt.Fprintln(out, "未识别到已知 CMS。")
	} else {
		fmt.Fprintf(out, "CMS: %s %s\n", cmsName, dash(cmsVersion))
		logger.Success("识别到 CMS: %s %s", cmsName, cmsVersion)
	}

	wafName := detectWAF(response, bodyText)
	modulekit.Section(out, "WAF 识别")
	if wafName == "" {
		fmt.Fprintln(out, "未检测到常见 WAF/CDN。")
	} else {
		fmt.Fprintf(out, "WAF: %s\n", wafName)
		logger.Success("检测到 WAF: %s", wafName)
	}

	stack := detectTechStack(response, bodyText)
	modulekit.Section(out, "技术栈")
	if len(stack) == 0 {
		fmt.Fprintln(out, "未识别到明显技术栈特征。")
	} else {
		fmt.Fprintln(out, strings.Join(stack, "、"))
	}

	return nil
}

/*
detectCMS 按正文与响应头特征识别 CMS 并提取版本。

参数:
  - response (*http.Response): HTTP 响应。
  - body (string): 响应体。

返回:
  - string: CMS 名称。
  - string: 版本号，未提取到返回空串。
*/
func detectCMS(response *http.Response, body string) (string, string) {
	lowerBody := strings.ToLower(body)
	for _, cms := range CMSFingerprints {
		matchCount := 0
		for _, pattern := range cms.Body {
			if strings.Contains(lowerBody, strings.ToLower(pattern)) {
				matchCount++
			}
		}
		for headerKey, headerValue := range cms.Header {
			if value := response.Header.Get(headerKey); value != "" {
				if headerValue == "" || strings.Contains(strings.ToLower(value), strings.ToLower(headerValue)) {
					matchCount += 2
				}
			}
		}
		if matchCount >= 1 {
			return cms.Name, extractCMSVersion(cms.Name, body)
		}
	}
	return "", ""
}

/*
detectWAF 按响应头与正文特征识别 WAF/CDN。

参数:
  - response (*http.Response): HTTP 响应。
  - body (string): 响应体。

返回:
  - string: WAF 名称，未识别返回空串。
*/
func detectWAF(response *http.Response, body string) string {
	lowerBody := strings.ToLower(body)
	for _, waf := range WAFFingerprints {
		for headerKey, headerValue := range waf.Header {
			if value := response.Header.Get(headerKey); value != "" {
				if headerValue == "" || strings.Contains(strings.ToLower(value), strings.ToLower(headerValue)) {
					return waf.Name
				}
			}
		}
		for _, pattern := range waf.Body {
			if strings.Contains(lowerBody, strings.ToLower(pattern)) {
				return waf.Name
			}
		}
	}
	return ""
}

/*
detectTechStack 按正文与 Cookie 识别语言与前端技术栈。

参数:
  - response (*http.Response): HTTP 响应。
  - body (string): 响应体。

返回:
  - []string: 去重后的技术栈列表。
*/
func detectTechStack(response *http.Response, body string) []string {
	var stack []string
	lowerBody := strings.ToLower(body)

	if strings.Contains(lowerBody, "php") || strings.Contains(lowerBody, ".php") {
		stack = appendUnique(stack, "PHP")
	}
	if strings.Contains(lowerBody, "java") || strings.Contains(lowerBody, ".jsp") || strings.Contains(lowerBody, ".do") || strings.Contains(lowerBody, ".action") {
		stack = appendUnique(stack, "Java")
	}
	if strings.Contains(lowerBody, "asp.net") || strings.Contains(lowerBody, ".aspx") {
		stack = appendUnique(stack, "ASP.NET")
	}
	if strings.Contains(lowerBody, "python") || strings.Contains(lowerBody, "django") || strings.Contains(lowerBody, "flask") {
		stack = appendUnique(stack, "Python")
	}
	if strings.Contains(lowerBody, "node.js") || strings.Contains(lowerBody, "nodejs") || strings.Contains(lowerBody, "express") {
		stack = appendUnique(stack, "Node.js")
	}
	if strings.Contains(lowerBody, "vue") {
		stack = appendUnique(stack, "Vue.js")
	}
	if strings.Contains(lowerBody, "react") {
		stack = appendUnique(stack, "React")
	}
	if strings.Contains(lowerBody, "jquery") {
		stack = appendUnique(stack, "jQuery")
	}
	if strings.Contains(lowerBody, "bootstrap") {
		stack = appendUnique(stack, "Bootstrap")
	}

	for _, cookie := range response.Cookies() {
		name := strings.ToLower(cookie.Name)
		switch {
		case strings.Contains(name, "phpsessid"):
			stack = appendUnique(stack, "PHP (Session)")
		case strings.Contains(name, "jsessionid"):
			stack = appendUnique(stack, "Java (JSP)")
		case strings.Contains(name, "aspsession") || strings.Contains(name, "asp.net_sessionid"):
			stack = appendUnique(stack, "ASP.NET (Session)")
		}
	}
	return stack
}

/*
extractCMSVersion 用 CMS 专属正则从正文提取版本号。

参数:
  - cmsName (string): CMS 名称。
  - body (string): 响应体。

返回:
  - string: 版本号，未提取到返回空串。
*/
func extractCMSVersion(cmsName string, body string) string {
	patterns, ok := cmsVersionPatterns[cmsName]
	if !ok {
		return ""
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		matches := re.FindStringSubmatch(strings.ToLower(body))
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

/*
appendUnique 在切片中追加去重后的条目。

参数:
  - items ([]string): 现有切片。
  - item (string): 待追加条目。

返回:
  - []string: 追加后的切片。
*/
func appendUnique(items []string, item string) []string {
	for _, existing := range items {
		if strings.EqualFold(existing, item) {
			return items
		}
	}
	return append(items, item)
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
