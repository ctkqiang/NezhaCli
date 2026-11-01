// CVE 静态数据移植自 vecmap 项目 internal/constant/cve.go。
// 每一条目都保留官方来源链接，版本匹配由本文件内的区间函数完成。
package vecmap

import (
	"fmt"
	"strconv"
	"strings"
)

// CVEEntry 描述一条与向量数据库相关的公开漏洞。
type CVEEntry struct {
	ID        string
	Vendor    VendorID
	TitleZH   string
	Severity  string
	CVSS      float64
	Affected  string
	Fixed     string
	DetailZH  string
	TTP       string
	Reference string
	Ranges    []VersionRange
}

// VersionRange 是左闭右闭的版本区间，空字符串表示该侧无边界。
type VersionRange struct {
	Min string
	Max string
}

// CVEs 是内置漏洞种子库，仅收录有官方来源的条目。
var CVEs = []CVEEntry{
	{
		ID: "CVE-2025-67818", Vendor: VendorWeaviate, TitleZH: "备份恢复路径穿越（ZipSlip）",
		Severity: "HIGH", CVSS: 7.2,
		Affected: "<= 1.30.19 / 1.31.x <= 1.31.18 / 1.32.x <= 1.32.15 / 1.33.x <= 1.33.3",
		Fixed:    "1.30.20 / 1.31.19 / 1.32.16 / 1.33.4",
		DetailZH: "具备写入对象权限的攻击者可在备份条目中使用符号链接、绝对路径或 .. 逃逸恢复根目录，在服务进程权限范围内创建或覆盖任意文件。",
		TTP:      "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2025-67818",
		Ranges: []VersionRange{{Max: "1.30.19"}, {Min: "1.31.0", Max: "1.31.18"}, {Min: "1.32.0", Max: "1.32.15"}, {Min: "1.33.0", Max: "1.33.3"}},
	},
	{
		ID: "CVE-2025-67819", Vendor: VendorWeaviate, TitleZH: "分片迁移接口路径穿越（任意文件读取）",
		Severity: "HIGH", CVSS: 8.7,
		Affected: "1.30.0-1.30.19 / 1.31.18 / 1.32.15 / 1.33.3",
		Fixed:    "1.30.20 / 1.31.19 / 1.32.16 / 1.33.4",
		DetailZH: "GetFile 接口未校验 fileName 参数，攻击者可利用 ../ 或绝对路径读取服务进程可访问的任意文件；Shard Movement API 默认关闭。",
		TTP:      "T1005", Reference: "https://github.com/advisories/GHSA-hmmh-292h-3364",
		Ranges: []VersionRange{{Min: "1.30.0", Max: "1.30.19"}, {Min: "1.31.0", Max: "1.31.18"}, {Min: "1.32.0", Max: "1.32.15"}, {Min: "1.33.0", Max: "1.33.3"}},
	},
	{
		ID: "CVE-2026-11500", Vendor: VendorWeaviate, TitleZH: "静态 API Key 校验缺陷导致越权",
		Severity: "MEDIUM", CVSS: 5.0,
		Affected: "<= 1.37.7", Fixed: "1.38.0-rc.0",
		DetailZH: "apikey/client.go 的 validateConfig 对 StaticApiKey 处理不当，可导致授权绕过；利用需较低权限的已认证账户。",
		TTP:      "T1078", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-11500",
		Ranges: []VersionRange{{Max: "1.37.7"}},
	},
	{
		ID: "CVE-2024-3829", Vendor: VendorQdrant, TitleZH: "快照恢复任意文件读写",
		Severity: "CRITICAL", CVSS: 9.8,
		Affected: "< 1.9.0", Fixed: "1.9.0",
		DetailZH: "快照恢复过程未限制符号链接，攻击者可构造快照实现任意文件读取与写入，进而可能接管主机。",
		TTP:      "T1190", Reference: "https://github.com/advisories/GHSA-7m75-x27w-r52r",
		Ranges: []VersionRange{{Max: "1.8.9"}},
	},
	{
		ID: "CVE-2026-25628", Vendor: VendorQdrant, TitleZH: "/logger 接口任意文件追加写入",
		Severity: "HIGH", CVSS: 8.8,
		Affected: ">= 1.9.3, < 1.16.0", Fixed: "1.16.0",
		DetailZH: "/logger 接口接受攻击者可控的 on_disk.log_file 路径，只读权限即可向任意文件追加内容，可改写配置并提升权限。",
		TTP:      "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-25628",
		Ranges: []VersionRange{{Min: "1.9.3", Max: "1.15.5"}},
	},
	{
		ID: "GHSA-frc7-44gm-99qq", Vendor: VendorQdrant, TitleZH: "分布式模式下内部 gRPC 无鉴权",
		Severity: "CRITICAL", CVSS: 9.8,
		Affected: "< 1.20.0（启用 cluster 的内部端口）", Fixed: "1.20.0",
		DetailZH: "分布式部署时内部 gRPC 端口默认不要求鉴权，可调用 AddPeerToKnown 加入集群、读取分片数据或修改集群状态。",
		TTP:      "T1190", Reference: "https://github.com/qdrant/qdrant/security/advisories/GHSA-frc7-44gm-99qq",
		Ranges: []VersionRange{{Max: "1.19.9"}},
	},
	{
		ID: "GHSA-3gph-6c29-p29v", Vendor: VendorQdrant, TitleZH: "内部 gRPC 接受只读 Key 与 JWT",
		Severity: "HIGH", CVSS: 8.3,
		Affected: ">= 1.18.0, < 1.19.2", Fixed: "1.19.2",
		DetailZH: "启用 enforce_internal_auth 后内部端口仍接受只读 API Key 与任意 JWT，只读凭证即可执行内部写操作。",
		TTP:      "T1078", Reference: "https://github.com/qdrant/qdrant/security/advisories/GHSA-3gph-6c29-p29v",
		Ranges: []VersionRange{{Min: "1.18.0", Max: "1.19.1"}},
	},
	{
		ID: "CVE-2025-64513", Vendor: VendorMilvus, TitleZH: "Proxy 组件认证绕过",
		Severity: "CRITICAL", CVSS: 9.3,
		Affected: "< 2.4.24 / 2.5.x < 2.5.21 / 2.6.x < 2.6.5",
		Fixed:    "2.4.24 / 2.5.21 / 2.6.5",
		DetailZH: "未认证攻击者可绕过 Milvus Proxy 的全部认证机制获得管理权限，可读写删除数据并执行管理操作；缓解方式是网关侧移除 sourceID 请求头。",
		TTP:      "T1190", Reference: "https://github.com/milvus-io/milvus/security/advisories/GHSA-mhjq-8c7m-3f7p",
		Ranges: []VersionRange{{Max: "2.4.23"}, {Min: "2.5.0", Max: "2.5.20"}, {Min: "2.6.0", Max: "2.6.4"}},
	},
	{
		ID: "CVE-2026-26190", Vendor: VendorMilvus, TitleZH: "9091 端口默认暴露导致认证绕过",
		Severity: "CRITICAL", CVSS: 9.8,
		Affected: "< 2.5.27 / 2.6.x < 2.6.10", Fixed: "2.5.27 / 2.6.10",
		DetailZH: "Milvus 默认开放 9091 端口，认证中间件未覆盖该端口上的接口，攻击者可绕过 REST API 鉴权。",
		TTP:      "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-26190",
		Ranges: []VersionRange{{Max: "2.5.26"}, {Min: "2.6.0", Max: "2.6.9"}},
	},
	{
		ID: "CVE-2026-69111", Vendor: VendorMilvus, TitleZH: "9091 管理接口未鉴权拒绝服务",
		Severity: "HIGH", CVSS: 7.5,
		Affected: "<= 2.6.22 与 3.0.0", Fixed: "2.6.23+",
		DetailZH: "管理服务 9091 的 /management/stop 未受 REST 鉴权中间件保护，攻击者可传入 role 参数停止 proxy、datanode 或 querynode。",
		TTP:      "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-69111",
		Ranges: []VersionRange{{Max: "2.6.22"}, {Min: "3.0.0", Max: "3.0.0"}},
	},
	{
		ID: "CVE-2026-45829", Vendor: VendorChroma, TitleZH: "预认证代码注入（trust_remote_code）",
		Severity: "CRITICAL", CVSS: 9.3,
		Affected: ">= 1.0.0, <= 1.5.9", Fixed: "暂无",
		DetailZH: "未认证攻击者可在创建集合时传入恶意模型仓库并令 trust_remote_code 为 true，在服务端执行任意代码。",
		TTP:      "T1190", Reference: "https://github.com/advisories/GHSA-f4j7-r4q5-qw2c",
		Ranges: []VersionRange{{Min: "1.0.0", Max: "1.5.9"}},
	},
	{
		ID: "CVE-2026-45831", Vendor: VendorChroma, TitleZH: "RBAC 未校验租户与集合归属",
		Severity: "HIGH", CVSS: 8.8,
		Affected: ">= 0.5.0, <= 1.5.9", Fixed: "暂无",
		DetailZH: "SimpleRBACAuthorizationProvider 只校验权限名，不校验所属租户/数据库/集合，导致跨租户操作。",
		TTP:      "T1078", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-45831",
		Ranges: []VersionRange{{Min: "0.5.0", Max: "1.5.9"}},
	},
	{
		ID: "CVE-2026-92782", Vendor: VendorChroma, TitleZH: "集合 ID 解析绕过租户隔离",
		Severity: "HIGH", CVSS: 8.1,
		Affected: "<= 1.5.9", Fixed: "暂无",
		DetailZH: "解析集合时未校验路径中的 tenant 与 database 段，已认证攻击者知道集合 UUID 即可跨租户读取或修改数据。",
		TTP:      "T1213", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-92782",
		Ranges: []VersionRange{{Max: "1.5.9"}},
	},
	{
		ID: "CVE-2026-85664", Vendor: VendorChroma, TitleZH: "HNSW 参数缺少上界导致内存耗尽",
		Severity: "HIGH", CVSS: 7.5,
		Affected: "<= 1.5.9", Fixed: "暂无",
		DetailZH: "创建集合时未校验 max_neighbors、ef_construction、ef_search 的上界，未认证攻击者可传入超大值在索引压缩阶段耗尽内存。",
		TTP:      "T1190", Reference: "https://nvd.nist.gov/vuln/detail/CVE-2026-85664",
		Ranges: []VersionRange{{Max: "1.5.9"}},
	},
}

/*
MatchCVE 返回给定厂商与版本命中的 CVE 列表。
版本为空时只按厂商过滤；区间匹配基于数值比较的语义化版本。

参数:
  - vendor (VendorID): 已识别厂商。
  - version (string): 已识别版本，例如 "1.12.3"。

返回:
  - []CVEEntry: 命中的 CVE 条目。
*/
func MatchCVE(vendor VendorID, version string) []CVEEntry {
	matches := make([]CVEEntry, 0, 4)
	for _, entry := range CVEs {
		if entry.Vendor != vendor {
			continue
		}
		if version == "" || versionInRanges(version, entry.Ranges) {
			matches = append(matches, entry)
		}
	}
	return matches
}

/*
LookupCVE 按编号查找单条内置公告。

参数:
  - id (string): CVE 或 GHSA 编号。

返回:
  - CVEEntry: 匹配的条目。
  - bool: 是否存在该条目。
*/
func LookupCVE(id string) (CVEEntry, bool) {
	for _, entry := range CVEs {
		if strings.EqualFold(entry.ID, id) {
			return entry, true
		}
	}
	return CVEEntry{}, false
}

/*
versionInRanges 判断版本是否落入任一受影响区间。

参数:
  - version (string): 待判断版本。
  - ranges ([]VersionRange): 受影响区间列表。

返回:
  - bool: 命中任一区间返回 true；版本非法且存在无上界区间时按命中处理。
*/
func versionInRanges(version string, ranges []VersionRange) bool {
	if len(ranges) == 0 {
		return true
	}
	for _, versionRange := range ranges {
		if versionRange.Min != "" && compareVersions(version, versionRange.Min) < 0 {
			continue
		}
		if versionRange.Max != "" && compareVersions(version, versionRange.Max) > 0 {
			continue
		}
		return true
	}
	return false
}

/*
compareVersions 按数值比较两个语义化版本，忽略后缀。
返回值语义与 strings.Compare 一致：a<b 为 -1，相等为 0，a>b 为 1。

参数:
  - a (string): 左操作数版本。
  - b (string): 右操作数版本。

返回:
  - int: 比较结果。
*/
func compareVersions(a string, b string) int {
	aParts := splitVersion(a)
	bParts := splitVersion(b)

	length := len(aParts)
	if len(bParts) > length {
		length = len(bParts)
	}
	for i := 0; i < length; i++ {
		var aNumber, bNumber int
		if i < len(aParts) {
			aNumber, _ = strconv.Atoi(aParts[i])
		}
		if i < len(bParts) {
			bNumber, _ = strconv.Atoi(bParts[i])
		}
		switch {
		case aNumber < bNumber:
			return -1
		case aNumber > bNumber:
			return 1
		}
	}
	return 0
}

/*
splitVersion 把版本号按点拆分为纯数字段，剔除 rc/beta 等后缀。

参数:
  - version (string): 原始版本号。

返回:
  - []string: 数字段列表。
*/
func splitVersion(version string) []string {
	version = strings.TrimSpace(version)
	fields := strings.FieldsFunc(version, func(char rune) bool {
		return char == '-' || char == '+' || char == '_'
	})
	parts := strings.Split(fields[0], ".")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

/*
SeverityLabel 返回严重性级别的中文标签。

参数:
  - severity (string): 原始级别，例如 "CRITICAL"。

返回:
  - string: 中文标签。
*/
func SeverityLabel(severity string) string {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return "严重"
	case "HIGH":
		return "高危"
	case "MEDIUM":
		return "中危"
	case "LOW":
		return "低危"
	default:
		return fmt.Sprintf("未知(%s)", severity)
	}
}
