package test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ctkqiang/nezha_cli/internal/core"
	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/structure"
	"github.com/ctkqiang/nezha_cli/modules/cve_2025_14847"
	"github.com/ctkqiang/nezha_cli/modules/cve_2025_4334"
	"github.com/ctkqiang/nezha_cli/modules/cve_2025_66478"
	"github.com/ctkqiang/nezha_cli/modules/mitre"
	"github.com/ctkqiang/nezha_cli/modules/payloads"
	"github.com/ctkqiang/nezha_cli/modules/webfinger"
	"github.com/ctkqiang/nezha_cli/pkg/vecmap"
)

/*
TestVecmapCVE 验证 CVE 版本区间匹配与厂商过滤。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestVecmapCVE(t *testing.T) {
	matches := vecmap.MatchCVE(vecmap.VendorQdrant, "1.12.3")
	if len(matches) == 0 {
		t.Fatal("Qdrant 1.12.3 应命中 CVE 条目")
	}
	found := false
	for _, entry := range matches {
		if entry.ID == "CVE-2026-25628" {
			found = true
		}
	}
	if !found {
		t.Fatalf("应命中 CVE-2026-25628: %v", matches)
	}

	legacy := vecmap.MatchCVE(vecmap.VendorQdrant, "1.8.5")
	legacyFound := false
	for _, entry := range legacy {
		if entry.ID == "CVE-2024-3829" {
			legacyFound = true
		}
	}
	if !legacyFound {
		t.Fatalf("1.8.5 应命中 CVE-2024-3829: %v", legacy)
	}

	safe := vecmap.MatchCVE(vecmap.VendorQdrant, "1.16.1")
	for _, entry := range safe {
		if entry.ID == "CVE-2024-3829" || entry.ID == "CVE-2026-25628" {
			t.Fatalf("已修复版本不应命中 %s", entry.ID)
		}
	}

	if _, ok := vecmap.LookupCVE("CVE-2026-92782"); !ok {
		t.Fatal("应能按编号查找到 Chroma 条目")
	}
	if vecmap.SeverityLabel("CRITICAL") != "严重" {
		t.Fatalf("级别标签错误: %s", vecmap.SeverityLabel("CRITICAL"))
	}
	if entry, ok := vecmap.LookupMITRE("T1190"); !ok || entry.NameZH != "利用面向公众的应用" {
		t.Fatalf("MITRE 目录缺失或名称错误: %+v", entry)
	}
}

/*
TestVecmapParseTarget 验证目标解析的端口与方案推断。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestVecmapParseTarget(t *testing.T) {
	target, err := vecmap.ParseTarget("https://10.0.0.5:8443")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if target.Host != "10.0.0.5" || target.Port != 8443 || target.Scheme != "https" {
		t.Fatalf("目标解析错误: %+v", target)
	}

	bare, err := vecmap.ParseTarget("10.0.0.5")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if bare.Port != 6333 {
		t.Fatalf("默认端口错误: %d", bare.Port)
	}
}

/*
TestPayloadsModule 验证内置字典非空且支持关键词过滤。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestPayloadsModule(t *testing.T) {
	module := payloads.New()
	if module.Meta().Name != "payloads" {
		t.Fatalf("模块名错误: %s", module.Meta().Name)
	}

	buffer := &bytes.Buffer{}
	err := module.Run(context.Background(), model.Options{"QUERY": "sleep", "LIMIT": "10"}, buffer)
	if err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !strings.Contains(buffer.String(), "SLEEP") {
		t.Fatalf("sleep 过滤应命中: %s", buffer.String())
	}

	buffer.Reset()
	if err := module.Run(context.Background(), model.Options{"QUERY": "不存在的关键词"}, buffer); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if strings.Contains(buffer.String(), " 1. ") {
		t.Fatalf("不存在的关键词不应命中条目: %s", buffer.String())
	}
}

/*
TestMitreCatalog 验证战术与技术目录数据完整性。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestMitreCatalog(t *testing.T) {
	if len(mitre.Tactics) != 25 {
		t.Fatalf("战术数量错误: %d", len(mitre.Tactics))
	}
	if len(mitre.Techniques) != 27 {
		t.Fatalf("技术数量错误: %d", len(mitre.Techniques))
	}

	module := mitre.New()
	buffer := &bytes.Buffer{}
	if err := module.Run(context.Background(), model.Options{"TACTIC": "BB22"}, buffer); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !strings.Contains(buffer.String(), "已知 CVE 检测") {
		t.Fatalf("BB22 过滤应命中技术: %s", buffer.String())
	}

	buffer.Reset()
	if err := module.Run(context.Background(), model.Options{"TECHNIQUE": "BB10.001"}, buffer); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	if !strings.Contains(buffer.String(), "SQL 注入") {
		t.Fatalf("技术详情缺失: %s", buffer.String())
	}
}

/*
TestWebfinger 验证 CMS 与 WAF 指纹识别。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestWebfinger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Powered-By", "ThinkPHP")
		writer.Header().Set("Server", "cloudflare")
		writer.Header().Set("CF-RAY", "abc123")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("<html><body>ThinkPHP 5.0.24 powered page</body></html>"))
	}))
	defer server.Close()

	module := webfinger.New()
	buffer := &bytes.Buffer{}
	if err := module.Run(context.Background(), model.Options{"URL": server.URL}, buffer); err != nil {
		t.Fatalf("执行失败: %v", err)
	}
	output := buffer.String()
	if !strings.Contains(output, "ThinkPHP") {
		t.Fatalf("应识别 ThinkPHP: %s", output)
	}
	if !strings.Contains(output, "CloudFlare") {
		t.Fatalf("应识别 CloudFlare: %s", output)
	}
	if !strings.Contains(output, "PHP") {
		t.Fatalf("应识别 PHP 技术栈: %s", output)
	}
}

/*
TestCVE4334Helpers 验证载荷构造与响应判据。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestCVE4334Helpers(t *testing.T) {
	values := cve_2025_4334.BuildRegistrationPayload("nonce123", "7", "/register/", "u", "e@x.com", "p")
	if values.Get("wpr_nonce") != "nonce123" || values.Get("wpr_form_id") != "7" {
		t.Fatalf("表单字段构造错误: %v", values)
	}
	if values.Get("wpr[wp_field][role]") != "administrator" {
		t.Fatalf("role 字段必须为 administrator: %v", values)
	}
	if !cve_2025_4334.AnalyzeResponse([]byte(`{"success":true,"user_id":3}`), 200) {
		t.Fatal("success+user_id 应判定成功")
	}
	if cve_2025_4334.AnalyzeResponse([]byte("denied"), 403) {
		t.Fatal("403 不应判定成功")
	}
}

/*
TestCVE66478Analyze 验证 React2Shell 响应判据。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestCVE66478Analyze(t *testing.T) {
	vulnerable, digest := cve_2025_66478.AnalyzeResponse(500, []byte(`{"digest":"E{\"digest\":\"boom\"}"}`))
	if !vulnerable || digest == "" {
		t.Fatalf("500+digest 应判定存在漏洞: %v %q", vulnerable, digest)
	}

	safe, _ := cve_2025_66478.AnalyzeResponse(200, []byte("ok"))
	if safe {
		t.Fatal("200 响应不应判定存在漏洞")
	}
}

/*
TestCVE14847Verdict 验证版本结论表。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestCVE14847Verdict(t *testing.T) {
	verdict := cve_2025_14847.VersionVerdict("8.2.2")
	if !strings.Contains(verdict, "修复版本为 8.2.3") {
		t.Fatalf("8.2.2 应受影响: %s", verdict)
	}
	fixed := cve_2025_14847.VersionVerdict("8.2.3")
	if !strings.Contains(fixed, "不受该分支影响") {
		t.Fatalf("8.2.3 应已修复: %s", fixed)
	}
	eol := cve_2025_14847.VersionVerdict("3.6.1")
	if !strings.Contains(eol, "结束主流支持") {
		t.Fatalf("3.6.x 应为 EOL: %s", eol)
	}
}

/*
TestConsoleReportCommand 验证 report 命令导出 Markdown 报告。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestConsoleReportCommand(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	console := structure.New(registry)
	console.SetColor(false)
	console.SetInput(strings.NewReader(""))
	console.SetOutput(&bytes.Buffer{})

	if err := console.SelectModule("dns"); err != nil {
		t.Fatalf("选中模块失败: %v", err)
	}

	directory := t.TempDir()
	reportPath := filepath.Join(directory, "report.md")
	console.ExecuteOnce("report " + reportPath)

	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("报告未生成: %v", err)
	}
	text := string(content)
	if !strings.Contains(text, "# 哪吒网络安全终端 · 评估报告") {
		t.Fatalf("报告缺少标题: %s", text)
	}
	if !strings.Contains(text, "DOMAIN") {
		t.Fatalf("报告缺少模块参数: %s", text)
	}
	if !strings.Contains(text, "授权声明") {
		t.Fatalf("报告缺少授权声明: %s", text)
	}
}

/*
TestMitreModuleRegistered 验证新模块已进入注册表并可检索。

参数:
  - t (*testing.T): 测试上下文。

返回:
  - 无。
*/
func TestMitreModuleRegistered(t *testing.T) {
	registry, err := core.LoadNative()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	for _, name := range []string{"vecmap", "mitre", "cve", "payloads", "webfinger", "cve_2025_14847", "cve_2025_4334", "cve_2025_66478"} {
		if _, ok := registry.Get(name); !ok {
			t.Fatalf("缺少模块 %s", name)
		}
	}
}
