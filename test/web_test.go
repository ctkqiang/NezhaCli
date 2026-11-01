package test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	websafe "github.com/ctkqiang/nezha_cli/pkg/web"
)

/*
TestWebAuditHeaders 验证安全响应头、Cookie 属性与服务器信息审计。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestWebAuditHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Strict-Transport-Security", "max-age=63072000")
		writer.Header().Set("Content-Security-Policy", "default-src 'self'")
		writer.Header().Set("X-Content-Type-Options", "nosniff")
		writer.Header().Set("Referrer-Policy", "no-referrer")
		writer.Header().Set("Permissions-Policy", "geolocation=()")
		writer.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		writer.Header().Set("Cross-Origin-Resource-Policy", "same-origin")
		writer.Header().Set("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Strict")
		writer.Header().Set("Server", "NezhaTest")
		writer.Header().Set("X-Powered-By", "Go")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := websafe.AuditHeaders(ctx, server.URL, 3*time.Second)
	if err != nil {
		t.Fatalf("审计失败: %v", err)
	}
	if report.StatusCode != http.StatusOK {
		t.Fatalf("状态码错误: %d", report.StatusCode)
	}
	if report.Server != "NezhaTest" || report.PoweredBy != "Go" {
		t.Fatalf("服务器信息错误: %q %q", report.Server, report.PoweredBy)
	}
	if len(report.Findings) != 10 {
		t.Fatalf("安全检查项数量错误: %d", len(report.Findings))
	}

	present := make(map[string]bool, len(report.Findings))
	for _, finding := range report.Findings {
		present[finding.Name] = finding.Present
	}
	if !present["Content-Security-Policy"] || !present["Strict-Transport-Security"] {
		t.Fatalf("已设置的响应头应被识别: %+v", present)
	}
	if present["X-Frame-Options"] {
		t.Fatal("未设置的 X-Frame-Options 不应标记为存在")
	}

	if len(report.Cookies) != 1 {
		t.Fatalf("Cookie 数量错误: %d", len(report.Cookies))
	}
	cookie := report.Cookies[0]
	if cookie.Name != "session" || !cookie.Secure || !cookie.HTTPOnly || cookie.SameSite != "Strict" {
		t.Fatalf("Cookie 属性错误: %+v", cookie)
	}
}

/*
TestWebAuditHeadersValidation 验证 URL 与协议校验。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestWebAuditHeadersValidation(t *testing.T) {
	ctx := context.Background()
	for _, target := range []string{"", "ftp://example.com", "http://"} {
		if _, err := websafe.AuditHeaders(ctx, target, time.Second); err == nil {
			t.Fatalf("非法 URL %q 应返回错误", target)
		}
	}
}

/*
TestWebFetchWellKnown 验证 robots.txt、sitemap.xml 与 security.txt 检查。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestWebFetchWellKnown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/robots.txt" {
			writer.Header().Set("Content-Type", "text/plain")
			_, _ = writer.Write([]byte("User-agent: *\nDisallow: /admin\n"))
			return
		}
		http.NotFound(writer, request)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	results, err := websafe.FetchWellKnown(ctx, server.URL, 3*time.Second)
	if err != nil {
		t.Fatalf("检查失败: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("标准文件数量错误: %d", len(results))
	}

	found := 0
	for _, result := range results {
		if result.Found {
			found++
			if result.Path != "/robots.txt" {
				t.Fatalf("只有 robots.txt 应命中: %+v", result)
			}
			if !strings.Contains(result.Snippet, "User-agent") {
				t.Fatalf("摘要内容错误: %q", result.Snippet)
			}
			if strings.ContainsAny(result.Snippet, "\n\r") {
				t.Fatalf("摘要应压缩为单行: %q", result.Snippet)
			}
		}
		if result.StatusCode == http.StatusNotFound && result.Found {
			t.Fatalf("404 不应视为命中: %+v", result)
		}
	}
	if found != 1 {
		t.Fatalf("命中数量错误: %d", found)
	}
}

/*
TestWebAuditMethods 验证 OPTIONS 与 Allow 头解析。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestWebAuditMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodOptions {
			http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		writer.Header().Set("Allow", "POST, GET, OPTIONS")
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	report, err := websafe.AuditMethods(ctx, server.URL, 3*time.Second)
	if err != nil {
		t.Fatalf("方法审计失败: %v", err)
	}
	if report.StatusCode != http.StatusNoContent {
		t.Fatalf("状态码错误: %d", report.StatusCode)
	}
	if strings.Join(report.Methods, ",") != "GET,OPTIONS,POST" {
		t.Fatalf("方法解析错误: %v", report.Methods)
	}
}

/*
TestWebInspectTLS 验证自签名证书的字段提取与信任状态。
httptest 的 TLS 证书不在系统信任链中，因此 Trusted 必须为 false。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestWebInspectTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("ok"))
	}))
	defer server.Close()

	host, portText, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatalf("解析测试服务器地址失败: %v", err)
	}
	port := 0
	for _, char := range portText {
		port = port*10 + int(char-'0')
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	info, err := websafe.InspectTLS(ctx, host, port, 3*time.Second)
	if err != nil {
		t.Fatalf("TLS 检查失败: %v", err)
	}
	if info.Host != host || info.Port != port {
		t.Fatalf("目标信息错误: %s:%d", info.Host, info.Port)
	}
	if info.TLSVersion == "" || info.CipherSuite == "" {
		t.Fatalf("TLS 参数缺失: %+v", info)
	}
	if !info.Valid {
		t.Fatalf("测试证书应在有效期内: %+v", info)
	}
	if info.Trusted {
		t.Fatal("自签名证书不应通过系统信任校验")
	}
	if info.VerifyError == "" {
		t.Fatal("未受信任证书应记录校验错误")
	}
	if info.Subject == "" || info.Issuer == "" {
		t.Fatalf("证书主题或签发者缺失: %+v", info)
	}
}

/*
TestWebInspectTLSValidation 验证空主机与非法端口。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestWebInspectTLSValidation(t *testing.T) {
	ctx := context.Background()
	if _, err := websafe.InspectTLS(ctx, "", 443, time.Second); err == nil {
		t.Fatal("空主机应返回错误")
	}
	if _, err := websafe.InspectTLS(ctx, "127.0.0.1", 0, time.Second); err == nil {
		t.Fatal("非法端口应返回错误")
	}
	if _, err := websafe.InspectURLTLS(ctx, "http://example.com", time.Second); err == nil {
		t.Fatal("非 HTTPS URL 应返回错误")
	}
}
