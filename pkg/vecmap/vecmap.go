// vecmap 包移植自作者的 vecmap 项目：向量数据库攻击面的只读评估后端。
//
// 与上游保持一致的三条铁律：
//  1. 只读：仅允许 GET/HEAD/OPTIONS 与只读 POST（Milvus v2 集合列表）；
//  2. 有界：响应体读取上限 1MB，单次探测微超时；
//  3. 可核查：每个 CVE 结论都附带官方来源链接。
package vecmap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// maxBodyBytes 是单次响应体读取上限，防止恶意端点拖垮移动端内存。
	maxBodyBytes = 1 << 20

	// redisTimeout 是 Redis TCP 指纹的超时预算。
	redisTimeout = 2 * time.Second
)

// VendorID 是向量数据库厂商标识。
type VendorID string

const (
	// VendorUnknown 表示未识别的厂商。
	VendorUnknown VendorID = "未知"

	// VendorQdrant 表示 Qdrant 向量库。
	VendorQdrant VendorID = "Qdrant"

	// VendorWeaviate 表示 Weaviate 向量库。
	VendorWeaviate VendorID = "Weaviate"

	// VendorMilvus 表示 Milvus 向量库。
	VendorMilvus VendorID = "Milvus"

	// VendorChroma 表示 Chroma 向量库。
	VendorChroma VendorID = "Chroma"

	// VendorElasticsearch 表示 Elasticsearch。
	VendorElasticsearch VendorID = "Elasticsearch"

	// VendorOpenSearch 表示 OpenSearch。
	VendorOpenSearch VendorID = "OpenSearch"

	// VendorTypesense 表示 Typesense。
	VendorTypesense VendorID = "Typesense"

	// VendorVespa 表示 Vespa。
	VendorVespa VendorID = "Vespa"

	// VendorRedis 表示 Redis（向量检索模式）。
	VendorRedis VendorID = "Redis"
)

// defaultPorts 是未显式指定端口时的候选探测端口。
var defaultPorts = []int{6333, 8080, 19530, 8000, 9200, 8108, 6379}

// Target 描述一个已标准化的探测目标。
type Target struct {
	Raw    string
	Scheme string
	Host   string
	Port   int
}

// ProbeResult 是一次指纹识别的结果。
type ProbeResult struct {
	Vendor       VendorID
	Product      string
	Version      string
	AuthRequired bool
	Server       string
	Evidence     []string
}

// Collection 描述一条只读枚举到的集合或索引。
type Collection struct {
	Name   string
	Fields []string
	Count  int64
}

// httpProbe 携带共享 HTTP 客户端与超时预算。
type httpProbe struct {
	client  *http.Client
	base    string
	timeout time.Duration
}

/*
ParseTarget 解析目标字符串，支持 URL、host 与 host:port 三种写法。
未指定端口时使用 6333 作为默认端口，探测阶段会自动补齐其余候选端口。

参数:
  - raw (string): 原始目标，例如 "http://10.0.0.5:6333" 或 "10.0.0.5"。

返回:
  - Target: 标准化目标。
  - error: 输入为空或 URL 无法解析时返回错误。
*/
func ParseTarget(raw string) (Target, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, fmt.Errorf("目标不能为空")
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return Target{}, fmt.Errorf("解析目标失败: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return Target{}, fmt.Errorf("目标缺少主机名")
	}

	port := 6333
	if parsed.Port() != "" {
		port, err = strconv.Atoi(parsed.Port())
		if err != nil || port < 1 || port > 65535 {
			return Target{}, fmt.Errorf("端口非法: %q", parsed.Port())
		}
	}

	scheme := parsed.Scheme
	if scheme == "" {
		scheme = "http"
	}

	return Target{Raw: raw, Scheme: scheme, Host: host, Port: port}, nil
}

/*
Identify 识别目标上运行的向量数据库并返回指纹。
adapter 为 auto 时依次探测候选厂商；指定具体厂商时只走该厂商的探测路径。

参数:
  - ctx (context.Context): 探测上下文。
  - target (Target): 标准化目标。
  - adapter (string): auto 或具体厂商标识。
  - timeout (time.Duration): 单次探测超时。

返回:
  - ProbeResult: 指纹结果；未能识别时 Vendor 为 VendorUnknown。
  - error: 全部候选端口不可达或请求失败时返回错误。
*/
func Identify(ctx context.Context, target Target, adapter string, timeout time.Duration) (ProbeResult, error) {
	adapter = strings.ToLower(strings.TrimSpace(adapter))
	if adapter == "auto" || adapter == "" {
		return identifyAuto(ctx, target, timeout)
	}

	vendor := vendorFromAdapter(adapter)
	if vendor == VendorUnknown {
		return ProbeResult{}, fmt.Errorf("未知适配器 %q，可选 auto/qdrant/weaviate/milvus/chroma/elasticsearch/opensearch/typesense/vespa/redis", adapter)
	}

	client := &http.Client{Timeout: timeout}
	probe := &httpProbe{client: client, base: baseURL(target), timeout: timeout}
	result, err := fingerprintVendor(ctx, probe, target, vendor)
	if err != nil {
		return ProbeResult{}, err
	}
	return result, nil
}

/*
Enumerate 只读枚举目标向量库的集合或索引。
依赖 Identify 先确定厂商；未识别时会返回错误。

参数:
  - ctx (context.Context): 枚举上下文。
  - target (Target): 标准化目标。
  - vendor (VendorID): 已识别的厂商。
  - timeout (time.Duration): 单次请求超时。

返回:
  - []Collection: 集合与索引列表。
  - error: 请求失败或厂商不支持枚举时返回错误。
*/
func Enumerate(ctx context.Context, target Target, vendor VendorID, timeout time.Duration) ([]Collection, error) {
	client := &http.Client{Timeout: timeout}
	probe := &httpProbe{client: client, base: baseURL(target), timeout: timeout}

	switch vendor {
	case VendorQdrant:
		return enumerateQdrant(ctx, probe)
	case VendorWeaviate:
		return enumerateWeaviate(ctx, probe)
	case VendorChroma:
		return enumerateChroma(ctx, probe)
	case VendorMilvus:
		return enumerateMilvus(ctx, probe)
	case VendorElasticsearch, VendorOpenSearch:
		return enumerateElastic(ctx, probe)
	case VendorTypesense:
		return enumerateTypesense(ctx, probe)
	case VendorVespa:
		return enumerateVespa(ctx, probe)
	case VendorRedis:
		return nil, fmt.Errorf("Redis 枚举需执行 Redis 命令，超出只读探测范围")
	default:
		return nil, fmt.Errorf("厂商未识别，无法枚举")
	}
}

/*
identifyAuto 按候选端口与候选厂商顺序探测，取第一个可信指纹。
端口顺序依据向量库的常见默认端口排列，避免无谓的端口扫描。

参数:
  - ctx (context.Context): 探测上下文。
  - target (Target): 标准化目标。
  - timeout (time.Duration): 单次探测超时。

返回:
  - ProbeResult: 指纹结果。
  - error: 全部候选不可达时返回错误。
*/
func identifyAuto(ctx context.Context, target Target, timeout time.Duration) (ProbeResult, error) {
	client := &http.Client{Timeout: timeout}

	ports := []int{target.Port}
	for _, port := range defaultPorts {
		if port != target.Port {
			ports = append(ports, port)
		}
	}

	lastErr := errors.New("无候选端口")
	vendors := []VendorID{
		VendorQdrant, VendorWeaviate, VendorMilvus, VendorChroma,
		VendorElasticsearch, VendorOpenSearch, VendorTypesense, VendorVespa,
	}
	for _, port := range ports {
		candidate := Target{Raw: target.Raw, Scheme: target.Scheme, Host: target.Host, Port: port}
		probe := &httpProbe{client: client, base: baseURL(candidate), timeout: timeout}
		for _, vendor := range vendors {
			result, err := fingerprintVendor(ctx, probe, candidate, vendor)
			if err != nil {
				lastErr = err
				continue
			}
			if result.Vendor != VendorUnknown {
				return result, nil
			}
		}

		if redis, err := fingerprintRedis(ctx, candidate); err == nil && redis.Vendor != VendorUnknown {
			return redis, nil
		}
	}

	return ProbeResult{}, fmt.Errorf("未能识别向量数据库（最后错误: %v）", lastErr)
}

/*
fingerprintVendor 按厂商分发到各自的指纹函数。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。
  - target (Target): 标准化目标。
  - vendor (VendorID): 候选厂商。

返回:
  - ProbeResult: 指纹结果；不匹配时 Vendor 为 VendorUnknown。
  - error: 请求失败时返回错误。
*/
func fingerprintVendor(ctx context.Context, probe *httpProbe, target Target, vendor VendorID) (ProbeResult, error) {
	switch vendor {
	case VendorQdrant:
		return fingerprintQdrant(ctx, probe)
	case VendorWeaviate:
		return fingerprintWeaviate(ctx, probe)
	case VendorMilvus:
		return fingerprintMilvus(ctx, probe)
	case VendorChroma:
		return fingerprintChroma(ctx, probe)
	case VendorElasticsearch:
		return fingerprintElastic(ctx, probe)
	case VendorOpenSearch:
		return fingerprintOpenSearch(ctx, probe)
	case VendorTypesense:
		return fingerprintTypesense(ctx, probe)
	case VendorVespa:
		return fingerprintVespa(ctx, probe)
	case VendorRedis:
		return fingerprintRedis(ctx, target)
	default:
		return ProbeResult{}, fmt.Errorf("不支持的厂商: %s", vendor)
	}
}

/*
fingerprintQdrant 识别 Qdrant：根路径 title/version、/healthz 与 /collections 结构。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintQdrant(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "qdrant"}
	body, status, header, err := probe.get(ctx, "/")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	if status >= 200 && status < 300 {
		var root map[string]any
		if err := json.Unmarshal(body, &root); err == nil {
			title := stringValue(root["title"])
			if strings.Contains(strings.ToLower(title), "qdrant") || strings.Contains(strings.ToLower(string(body)), "qdrant") {
				result.Vendor = VendorQdrant
				result.Version = stringValue(root["version"])
				result.Evidence = append(result.Evidence, "根路径返回 Qdrant 标识")
			}
		}
	}
	if result.Vendor == VendorUnknown {
		healthBody, healthStatus, _, _ := probe.get(ctx, "/healthz")
		if healthStatus >= 200 && healthStatus < 300 && strings.Contains(strings.ToLower(string(healthBody)), "healthz check passed") {
			result.Vendor = VendorQdrant
			result.Evidence = append(result.Evidence, "/healthz 返回 healthz check passed")
		}
	}
	if result.Vendor == VendorUnknown {
		collectionsBody, collectionsStatus, _, _ := probe.get(ctx, "/collections")
		if collectionsStatus >= 200 && collectionsStatus < 300 {
			var collections map[string]any
			if err := json.Unmarshal(collectionsBody, &collections); err == nil {
				if resultValue, ok := collections["result"].(map[string]any); ok {
					if _, ok := resultValue["collections"].([]any); ok {
						result.Vendor = VendorQdrant
						result.Evidence = append(result.Evidence, "/collections 结构匹配")
					}
				}
			}
		}
	}
	result.Server = header.Get("Server")
	return result, nil
}

/*
fingerprintWeaviate 识别 Weaviate：/v1/meta 版本、readiness 与 /v1/schema 结构。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintWeaviate(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "weaviate"}
	body, status, header, err := probe.get(ctx, "/v1/meta")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	result.Server = header.Get("Server")
	if status >= 200 && status < 300 {
		var meta map[string]any
		if err := json.Unmarshal(body, &meta); err == nil {
			if version := stringValue(meta["version"]); version != "" {
				result.Vendor = VendorWeaviate
				result.Version = version
				result.Evidence = append(result.Evidence, "/v1/meta 返回版本 "+version)
			}
		}
	}
	if result.Vendor == VendorUnknown && result.AuthRequired {
		result.Vendor = VendorWeaviate
		result.Evidence = append(result.Evidence, "/v1/meta 返回 401/403")
	}
	if result.Vendor == VendorUnknown {
		_, readyStatus, _, _ := probe.get(ctx, "/v1/.well-known/ready")
		if readyStatus >= 200 && readyStatus < 300 {
			result.Vendor = VendorWeaviate
			result.Evidence = append(result.Evidence, "readiness 端点可达")
		}
	}
	if result.Vendor == VendorUnknown {
		schemaBody, schemaStatus, _, _ := probe.get(ctx, "/v1/schema")
		if schemaStatus >= 200 && schemaStatus < 300 {
			var schema map[string]any
			if err := json.Unmarshal(schemaBody, &schema); err == nil {
				if _, ok := schema["classes"].([]any); ok {
					result.Vendor = VendorWeaviate
					result.Evidence = append(result.Evidence, "/v1/schema classes 结构匹配")
				}
			}
		}
	}
	return result, nil
}

/*
fingerprintMilvus 识别 Milvus REST 接口：/api/v1/health 与 /api/v1/version。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintMilvus(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "milvus"}
	body, status, header, err := probe.get(ctx, "/api/v1/health")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	result.Server = header.Get("Server")
	if status >= 200 && status < 300 {
		var health map[string]any
		if err := json.Unmarshal(body, &health); err == nil {
			statusValue := stringValue(health["status"])
			if strings.EqualFold(statusValue, "ok") || strings.Contains(strings.ToLower(string(body)), "milvus") {
				result.Vendor = VendorMilvus
				result.Evidence = append(result.Evidence, "/api/v1/health 返回 "+statusValue)
			}
		}
	}
	if result.Vendor != VendorUnknown {
		versionBody, versionStatus, _, _ := probe.get(ctx, "/api/v1/version")
		if versionStatus >= 200 && versionStatus < 300 {
			var versionMap map[string]any
			if err := json.Unmarshal(versionBody, &versionMap); err == nil {
				result.Version = stringValue(versionMap["version"])
			}
		}
	}
	return result, nil
}

/*
fingerprintChroma 识别 Chroma：v2/v1 版本接口与心跳接口。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintChroma(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "chroma"}
	body, status, header, err := probe.get(ctx, "/api/v2/version")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	result.Server = header.Get("Server")
	if status >= 200 && status < 300 {
		var versionMap map[string]any
		if err := json.Unmarshal(body, &versionMap); err == nil {
			if version := stringValue(versionMap["version"]); version != "" {
				result.Vendor = VendorChroma
				result.Version = version
				result.Evidence = append(result.Evidence, "/api/v2/version 返回 "+version)
			}
		}
	}
	if result.Vendor == VendorUnknown {
		heartbeatBody, heartbeatStatus, _, _ := probe.get(ctx, "/api/v1/heartbeat")
		if heartbeatStatus >= 200 && heartbeatStatus < 300 {
			var heartbeat map[string]any
			if err := json.Unmarshal(heartbeatBody, &heartbeat); err == nil {
				if _, ok := heartbeat["nanosecond heartbeat"]; ok {
					result.Vendor = VendorChroma
					result.Evidence = append(result.Evidence, "/api/v1/heartbeat 结构匹配")
				}
			}
		}
	}
	return result, nil
}

/*
fingerprintElastic 识别 Elasticsearch：根路径 tagline 与 version.number。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintElastic(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "elasticsearch"}
	body, status, header, err := probe.get(ctx, "/")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	result.Server = header.Get("Server")
	if status >= 200 && status < 300 {
		var root map[string]any
		if err := json.Unmarshal(body, &root); err == nil {
			tagline := strings.ToLower(stringValue(root["tagline"]))
			if strings.Contains(tagline, "you know, for search") || strings.Contains(strings.ToLower(string(body)), "you know, for search") {
				result.Vendor = VendorElasticsearch
				if versionMap, ok := root["version"].(map[string]any); ok {
					result.Version = stringValue(versionMap["number"])
				}
				result.Evidence = append(result.Evidence, "根路径返回 Elasticsearch 标识")
			}
		}
	}
	return result, nil
}

/*
fingerprintOpenSearch 识别 OpenSearch：根路径 tagline 与 version.number。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintOpenSearch(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "opensearch"}
	body, status, header, err := probe.get(ctx, "/")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	result.Server = header.Get("Server")
	if status >= 200 && status < 300 {
		var root map[string]any
		if err := json.Unmarshal(body, &root); err == nil {
			if strings.Contains(strings.ToLower(string(body)), "opensearch") || strings.Contains(strings.ToLower(string(body)), "the opensearch project") {
				result.Vendor = VendorOpenSearch
				if versionMap, ok := root["version"].(map[string]any); ok {
					result.Version = stringValue(versionMap["number"])
				}
				result.Evidence = append(result.Evidence, "根路径返回 OpenSearch 标识")
			}
		}
	}
	return result, nil
}

/*
fingerprintTypesense 识别 Typesense：/health 返回 {"ok":true}。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintTypesense(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "typesense"}
	body, status, header, err := probe.get(ctx, "/health")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	result.Server = header.Get("Server")
	if status >= 200 && status < 300 {
		var health map[string]any
		if err := json.Unmarshal(body, &health); err == nil {
			if okValue, ok := health["ok"]; ok {
				if strings.EqualFold(stringValue(okValue), "true") || okValue == true {
					result.Vendor = VendorTypesense
					result.Evidence = append(result.Evidence, "/health 返回 ok:true")
				}
			}
		}
	}
	if result.Vendor != VendorUnknown {
		debugBody, debugStatus, _, _ := probe.get(ctx, "/debug")
		if debugStatus >= 200 && debugStatus < 300 {
			var debug map[string]any
			if err := json.Unmarshal(debugBody, &debug); err == nil {
				result.Version = stringValue(debug["version"])
			}
		}
	}
	return result, nil
}

/*
fingerprintVespa 识别 Vespa：/ApplicationStatus 的 JSON 状态。

参数:
  - ctx (context.Context): 探测上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - ProbeResult: 指纹结果。
  - error: 请求失败时返回错误。
*/
func fingerprintVespa(ctx context.Context, probe *httpProbe) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "vespa"}
	body, status, header, err := probe.get(ctx, "/ApplicationStatus")
	if err != nil {
		return result, err
	}
	result.AuthRequired = status == http.StatusUnauthorized || status == http.StatusForbidden
	result.Server = header.Get("Server")
	if status >= 200 && status < 300 {
		var appStatus map[string]any
		if err := json.Unmarshal(body, &appStatus); err == nil {
			if _, ok := appStatus["status"]; ok || strings.Contains(strings.ToLower(string(body)), "vespa") {
				result.Vendor = VendorVespa
				result.Version = stringValue(appStatus["version"])
				result.Evidence = append(result.Evidence, "/ApplicationStatus 结构匹配")
			}
		}
	}
	return result, nil
}

/*
fingerprintRedis 通过 TCP 发送 INFO 命令识别 Redis 并提取版本。

参数:
  - ctx (context.Context): 探测上下文。
  - target (Target): 标准化目标。

返回:
  - ProbeResult: 指纹结果。
  - error: 连接失败或超时返回错误。
*/
func fingerprintRedis(ctx context.Context, target Target) (ProbeResult, error) {
	result := ProbeResult{Vendor: VendorUnknown, Product: "redis"}
	dialer := net.Dialer{Timeout: redisTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
	if err != nil {
		return result, err
	}
	defer conn.Close()

	deadline := time.Now().Add(redisTimeout)
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte("*1\r\n$4\r\nINFO\r\n")); err != nil {
		return result, err
	}

	scanner := bufio.NewScanner(io.LimitReader(conn, maxBodyBytes))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "redis_version:") {
			result.Vendor = VendorRedis
			result.Version = strings.TrimSpace(strings.TrimPrefix(line, "redis_version:"))
			result.Evidence = append(result.Evidence, "INFO 返回 redis_version")
		}
	}
	if result.Vendor == VendorUnknown {
		return result, fmt.Errorf("响应不含 redis_version，可能不是 Redis")
	}
	return result, nil
}

/*
enumerateQdrant 枚举 Qdrant /collections 的集合名。

参数:
  - ctx (context.Context): 枚举上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - []Collection: 集合列表。
  - error: 请求或解析失败时返回错误。
*/
func enumerateQdrant(ctx context.Context, probe *httpProbe) ([]Collection, error) {
	body, status, _, err := probe.get(ctx, "/collections")
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("/collections 返回 %d", status)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("解析集合列表失败: %w", err)
	}

	collections := make([]Collection, 0, 8)
	resultValue, _ := payload["result"].(map[string]any)
	items, _ := resultValue["collections"].([]any)
	for _, item := range items {
		if entry, ok := item.(map[string]any); ok {
			if name := stringValue(entry["name"]); name != "" {
				collections = append(collections, Collection{Name: name})
			}
		}
	}
	return collections, nil
}

/*
enumerateWeaviate 枚举 Weaviate /v1/schema 的类与属性。

参数:
  - ctx (context.Context): 枚举上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - []Collection: 类列表，Fields 为属性名。
  - error: 请求或解析失败时返回错误。
*/
func enumerateWeaviate(ctx context.Context, probe *httpProbe) ([]Collection, error) {
	body, status, _, err := probe.get(ctx, "/v1/schema")
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("/v1/schema 返回 %d", status)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("解析 schema 失败: %w", err)
	}

	collections := make([]Collection, 0, 8)
	classes, _ := payload["classes"].([]any)
	for _, item := range classes {
		if class, ok := item.(map[string]any); ok {
			collection := Collection{Name: stringValue(class["class"])}
			properties, _ := class["properties"].([]any)
			for _, property := range properties {
				if propertyMap, ok := property.(map[string]any); ok {
					if field := stringValue(propertyMap["name"]); field != "" {
						collection.Fields = append(collection.Fields, field)
					}
				}
			}
			collections = append(collections, collection)
		}
	}
	return collections, nil
}

/*
enumerateChroma 枚举 Chroma 集合：优先 v2 租户路径，失败时回落 v1。

参数:
  - ctx (context.Context): 枚举上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - []Collection: 集合列表，Count 为集合内文档数。
  - error: 请求或解析失败时返回错误。
*/
func enumerateChroma(ctx context.Context, probe *httpProbe) ([]Collection, error) {
	body, status, _, err := probe.get(ctx, "/api/v2/tenants/default_tenant/databases/default_database/collections")
	if err != nil || status < 200 || status >= 300 {
		body, status, _, err = probe.get(ctx, "/api/v1/collections")
		if err != nil {
			return nil, err
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("集合接口返回 %d", status)
		}
	}

	var items []map[string]any
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("解析集合列表失败: %w", err)
	}

	collections := make([]Collection, 0, len(items))
	for _, item := range items {
		collection := Collection{
			Name:  stringValue(item["name"]),
			Count: int64Value(item["count"]),
		}
		collections = append(collections, collection)
	}
	return collections, nil
}

/*
enumerateMilvus 通过只读 POST 调用 Milvus v2 集合列表接口。

参数:
  - ctx (context.Context): 枚举上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - []Collection: 集合列表。
  - error: 请求或解析失败时返回错误。
*/
func enumerateMilvus(ctx context.Context, probe *httpProbe) ([]Collection, error) {
	payload := strings.NewReader(`{"collectionNames":[]}`)
	body, status, err := probe.post(ctx, "/v2/vectordb/collections/list", payload)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("集合列表接口返回 %d", status)
	}

	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("解析集合列表失败: %w", err)
	}

	collections := make([]Collection, 0, 8)
	dataValue, _ := response["data"].([]any)
	for _, item := range dataValue {
		if entry, ok := item.(map[string]any); ok {
			if name := stringValue(entry["collectionName"]); name != "" {
				collections = append(collections, Collection{Name: name})
			}
		}
	}
	return collections, nil
}

/*
enumerateElastic 枚举 Elasticsearch/OpenSearch 的索引名与文档数。

参数:
  - ctx (context.Context): 枚举上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - []Collection: 索引列表。
  - error: 请求或解析失败时返回错误。
*/
func enumerateElastic(ctx context.Context, probe *httpProbe) ([]Collection, error) {
	body, status, _, err := probe.get(ctx, "/_cat/indices?format=json&h=index,docs.count")
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("索引接口返回 %d", status)
	}

	var rows []map[string]any
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("解析索引列表失败: %w", err)
	}

	collections := make([]Collection, 0, len(rows))
	for _, row := range rows {
		name := stringValue(row["index"])
		if name == "" {
			name = stringValue(row["indices"])
		}
		if strings.HasPrefix(name, ".") {
			continue
		}
		collections = append(collections, Collection{
			Name:  name,
			Count: int64Value(row["docs.count"]),
		})
	}
	return collections, nil
}

/*
enumerateTypesense 枚举 Typesense 集合名与文档数。

参数:
  - ctx (context.Context): 枚举上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - []Collection: 集合列表。
  - error: 请求或解析失败时返回错误。
*/
func enumerateTypesense(ctx context.Context, probe *httpProbe) ([]Collection, error) {
	body, status, _, err := probe.get(ctx, "/collections")
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("/collections 返回 %d", status)
	}

	var items []map[string]any
	if err := json.Unmarshal(body, &items); err != nil {
		return nil, fmt.Errorf("解析集合列表失败: %w", err)
	}

	collections := make([]Collection, 0, len(items))
	for _, item := range items {
		collections = append(collections, Collection{
			Name:  stringValue(item["name"]),
			Count: int64Value(item["num_documents"]),
		})
	}
	return collections, nil
}

/*
enumerateVespa 通过内容集群 API 枚举 schema 文档类型。

参数:
  - ctx (context.Context): 枚举上下文。
  - probe (*httpProbe): 共享 HTTP 探测工具。

返回:
  - []Collection: 文档类型列表。
  - error: 请求或解析失败时返回错误。
*/
func enumerateVespa(ctx context.Context, probe *httpProbe) ([]Collection, error) {
	body, status, _, err := probe.get(ctx, "/content/")
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("内容集群接口返回 %d", status)
	}

	var response map[string]any
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("解析 schema 失败: %w", err)
	}

	collections := make([]Collection, 0, 4)
	applications, _ := response["applications"].([]any)
	for _, item := range applications {
		if app, ok := item.(map[string]any); ok {
			if name := stringValue(app["id"]); name != "" {
				collections = append(collections, Collection{Name: name})
			}
		}
	}
	return collections, nil
}

/*
get 执行只读 GET 并限制响应体大小。

参数:
  - ctx (context.Context): 请求上下文。
  - path (string): 相对路径。

返回:
  - []byte: 响应体。
  - int: HTTP 状态码。
  - http.Header: 响应头。
  - error: 请求失败时返回错误。
*/
func (p *httpProbe) get(ctx context.Context, path string) ([]byte, int, http.Header, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base+path, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	response, err := p.client.Do(request)
	if err != nil {
		return nil, 0, nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return nil, response.StatusCode, response.Header, err
	}
	return body, response.StatusCode, response.Header, nil
}

/*
post 执行只读 POST（仅用于 Milvus v2 集合列表等需要 JSON 体的接口）。

参数:
  - ctx (context.Context): 请求上下文。
  - path (string): 相对路径。
  - body (io.Reader): JSON 请求体。

返回:
  - []byte: 响应体。
  - int: HTTP 状态码。
  - error: 请求失败时返回错误。
*/
func (p *httpProbe) post(ctx context.Context, path string, body io.Reader) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+path, body)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := p.client.Do(request)
	if err != nil {
		return nil, 0, err
	}
	defer response.Body.Close()

	payload, err := io.ReadAll(io.LimitReader(response.Body, maxBodyBytes))
	if err != nil {
		return nil, response.StatusCode, err
	}
	return payload, response.StatusCode, nil
}

/*
baseURL 生成目标的根 URL。

参数:
  - target (Target): 标准化目标。

返回:
  - string: 形如 http://host:port 的根地址。
*/
func baseURL(target Target) string {
	return fmt.Sprintf("%s://%s", target.Scheme, net.JoinHostPort(target.Host, strconv.Itoa(target.Port)))
}

/*
vendorFromAdapter 把适配器名归一化为厂商 ID。

参数:
  - adapter (string): 适配器名。

返回:
  - VendorID: 对应厂商；未知名称返回 VendorUnknown。
*/
func vendorFromAdapter(adapter string) VendorID {
	switch adapter {
	case "qdrant":
		return VendorQdrant
	case "weaviate":
		return VendorWeaviate
	case "milvus":
		return VendorMilvus
	case "chroma":
		return VendorChroma
	case "elasticsearch", "elastic":
		return VendorElasticsearch
	case "opensearch":
		return VendorOpenSearch
	case "typesense":
		return VendorTypesense
	case "vespa":
		return VendorVespa
	case "redis":
		return VendorRedis
	default:
		return VendorUnknown
	}
}

/*
stringValue 从 JSON 值中提取字符串，非字符串类型返回空串。

参数:
  - value (any): JSON 值。

返回:
  - string: 提取的字符串。
*/
func stringValue(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return ""
}

/*
int64Value 从 JSON 值中提取 int64，兼容 float64 与 json.Number。

参数:
  - value (any): JSON 值。

返回:
  - int64: 提取的整数，无法转换时返回 0。
*/
func int64Value(value any) int64 {
	switch number := value.(type) {
	case float64:
		return int64(number)
	case json.Number:
		result, _ := number.Int64()
		return result
	case int:
		return int64(number)
	case int64:
		return number
	default:
		return 0
	}
}
