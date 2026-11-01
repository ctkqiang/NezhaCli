package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// WellKnownResult 描述一个标准 Web 情报文件的可访问性。
type WellKnownResult struct {
	Path        string
	URL         string
	StatusCode  int
	ContentType string
	Found       bool
	Snippet     string
	Error       string
}

// MethodReport 描述目标 URL 的 HTTP 方法能力。
type MethodReport struct {
	StatusCode int
	Allow      string
	Methods    []string
}

/*
FetchWellKnown 检查目标站点的 robots.txt、sitemap.xml 与 security.txt。
该函数只发起只读 GET 请求，并限制读取前 4KB 内容，避免拉取大文件。

参数:
  - ctx (context.Context): 全局上下文。
  - rawURL (string): 目标站点 URL，必须包含 http:// 或 https://。
  - timeout (time.Duration): 单个请求超时。

返回:
  - []WellKnownResult: 三个标准路径的检查结果。
  - error: URL 非法时返回错误。
*/
func FetchWellKnown(ctx context.Context, rawURL string, timeout time.Duration) ([]WellKnownResult, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("URL 解析失败: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("仅支持 http:// 或 https:// URL")
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("URL 缺少主机名")
	}

	base := &url.URL{Scheme: parsed.Scheme, Host: parsed.Host}
	paths := []string{"/robots.txt", "/sitemap.xml", "/.well-known/security.txt"}
	client := &http.Client{Timeout: timeout}
	results := make([]WellKnownResult, 0, len(paths))

	for _, path := range paths {
		target := base.ResolveReference(&url.URL{Path: path})
		result := WellKnownResult{
			Path: path,
			URL:  target.String(),
		}

		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		request.Header.Set("User-Agent", "NezhaCLI/0.3 (+https://github.com/ctkqiang)")

		response, err := client.Do(request)
		if err != nil {
			result.Error = err.Error()
			results = append(results, result)
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		_ = response.Body.Close()
		result.StatusCode = response.StatusCode
		result.ContentType = response.Header.Get("Content-Type")
		result.Found = response.StatusCode == http.StatusOK
		result.Snippet = sanitizeSnippet(string(body))
		results = append(results, result)
	}

	return results, nil
}

/*
AuditMethods 向目标 URL 发送 OPTIONS 请求并解析 Allow 响应头。
部分服务器会禁用 OPTIONS 或返回 405，此时 Methods 为空但不会视为致命错误。

参数:
  - ctx (context.Context): 全局上下文。
  - rawURL (string): 目标 URL。
  - timeout (time.Duration): 请求超时。

返回:
  - MethodReport: 状态码、原始 Allow 头与解析后的方法列表。
  - error: URL 非法或请求失败时返回错误。
*/
func AuditMethods(ctx context.Context, rawURL string, timeout time.Duration) (MethodReport, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodOptions, rawURL, nil)
	if err != nil {
		return MethodReport{}, fmt.Errorf("创建 OPTIONS 请求失败: %w", err)
	}
	request.Header.Set("User-Agent", "NezhaCLI/0.3 (+https://github.com/ctkqiang)")

	client := &http.Client{Timeout: timeout}
	response, err := client.Do(request)
	if err != nil {
		return MethodReport{}, fmt.Errorf("OPTIONS 请求失败: %w", err)
	}
	defer response.Body.Close()

	allow := strings.TrimSpace(response.Header.Get("Allow"))
	methods := make([]string, 0)
	for _, method := range strings.Split(allow, ",") {
		method = strings.TrimSpace(method)
		if method != "" {
			methods = append(methods, method)
		}
	}
	sort.Strings(methods)

	return MethodReport{
		StatusCode: response.StatusCode,
		Allow:      allow,
		Methods:    methods,
	}, nil
}

/*
sanitizeSnippet 将响应内容压缩为单行可读摘要。
换行、制表符与控制字符会被替换为空格，避免污染终端输出。

参数:
  - content (string): 原始响应内容。

返回:
  - string: 最长 160 字符的单行摘要。
*/
func sanitizeSnippet(content string) string {
	content = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		if r < 0x20 || r > 0x7e {
			return '.'
		}
		return r
	}, content)
	content = strings.Join(strings.Fields(content), " ")
	if len(content) > 160 {
		content = content[:160]
	}
	return content
}
