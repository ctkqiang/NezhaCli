// subdomain 模块通过字典枚举、证书透明日志与 DNS 解析发现子域名。
package subdomain

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// maxCandidates 是单次枚举的子域名上限，避免移动端内存与 DNS 压力失控。
	maxCandidates = 3000

	// maxConcurrency 是 DNS 解析并发上限。
	maxConcurrency = 64

	// lookupTimeout 是单个子域名的解析超时。
	lookupTimeout = 3 * time.Second

	// crtMaxBytes 是 crt.sh 响应的读取上限。
	crtMaxBytes = 8 << 20

	// crtTimeout 是 crt.sh 查询超时。
	crtTimeout = 20 * time.Second
)

// builtinWords 是常见子域名字典，覆盖管理、接口、环境与基础设施命名。
var builtinWords = []string{
	"www", "www1", "www2", "m", "mobile", "wap", "app", "apps", "api", "api1", "api2", "apiv1", "apiv2",
	"admin", "administrator", "manage", "manager", "console", "dashboard", "portal", "panel", "backend",
	"login", "sso", "auth", "oauth", "id", "account", "accounts", "user", "users", "member",
	"mail", "webmail", "smtp", "pop", "imap", "mx", "mx1", "mx2", "email",
	"ftp", "sftp", "file", "files", "upload", "uploads", "download", "downloads", "static", "assets", "cdn",
	"img", "images", "image", "media", "video", "css", "js", "fonts",
	"dev", "develop", "developer", "development", "test", "testing", "qa", "uat", "stage", "staging", "pre", "preprod", "prod", "production",
	"demo", "sandbox", "beta", "alpha", "canary", "release", "preview",
	"blog", "news", "docs", "doc", "wiki", "help", "support", "service", "status", "health",
	"shop", "store", "pay", "payment", "order", "cart", "checkout",
	"crm", "erp", "oa", "hr", "finance", "report", "reports", "data", "db", "database", "mysql", "postgres", "redis", "mongo", "mongodb",
	"git", "gitlab", "github", "gitea", "svn", "jenkins", "ci", "cd", "build", "deploy", "registry", "docker", "k8s", "kubernetes",
	"monitor", "monitoring", "grafana", "prometheus", "kibana", "elastic", "elasticsearch", "log", "logs", "trace",
	"proxy", "gateway", "gw", "lb", "vpn", "remote", "ssh", "bastion", "jump",
	"ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "resolver",
	"intranet", "internal", "office", "home", "corp", "company", "cloud", "server", "host", "node",
	"old", "new", "backup", "bak", "archive", "mirror", "download2", "source", "src",
	"wap2", "touch", "h5", "mini", "mp", "wechat", "weixin", "alipay", "pay2",
	"idc", "ops", "devops", "sre", "security", "waf", "firewall", "proxy2",
	"search", "map", "map2", "geo", "location", "weather", "video2", "live",
	"open", "openapi", "partner", "agent", "supplier", "vendor", "b2b", "b2c",
	"career", "jobs", "recruit", "campus", "training", "learn", "edu",
	"forum", "bbs", "community", "feedback", "survey", "vote",
	"stats", "analytics", "track", "tracking", "metrics", "monitor2",
}

// Module 是子域名枚举模块。
type Module struct{}

// resolved 描述一个成功解析的子域名。
type resolved struct {
	name   string
	source string
	ips    []string
}

/*
New 创建子域名枚举模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回子域名枚举模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "subdomain",
		Aliases:  []string{"sub", "subenum"},
		Category: modulekit.CategoryRecon,
		Summary:  "内置字典与证书透明日志子域名枚举",
		Description: "合并内置字典、自定义字典与 crt.sh 证书透明日志生成候选子域名，\n" +
			"再通过标准库 DNS 解析器并发验证。自动执行通配符解析检测，\n" +
			"命中结果按名称排序并保留来源标记。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("DOMAIN", "根域名，例如 example.com", true, ""),
			modulekit.Option("WORDLIST", "自定义字典路径，每行一个子域名前缀", false, ""),
			modulekit.Option("THREADS", "DNS 解析并发数", false, "32"),
			modulekit.Option("CRT", "是否查询 crt.sh 证书透明日志", false, "true"),
		},
	}
}

/*
Run 收集候选子域名、解析并输出结果。

参数:
  - ctx (context.Context): 执行上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: 根域名为空、字典读取失败或执行被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	domain, err := normalizeDomain(options.Get("DOMAIN"))
	if err != nil {
		return err
	}

	candidates := make(map[string]string, len(builtinWords)+64)
	for _, word := range builtinWords {
		candidates[word+"."+domain] = "字典"
	}

	wordlist := strings.TrimSpace(options.Get("WORDLIST"))
	if wordlist != "" {
		words, err := readWordlist(wordlist)
		if err != nil {
			return err
		}
		for _, word := range words {
			name := word
			if !strings.HasSuffix(name, "."+domain) {
				name = word + "." + domain
			}
			if len(candidates) >= maxCandidates {
				logger.Warn("候选子域名达到上限 %d，忽略剩余字典项", maxCandidates)
				break
			}
			candidates[name] = "自定义字典"
		}
	}

	if options.Bool("CRT", true) {
		names, err := fetchCRTNames(ctx, domain)
		if err != nil {
			logger.Warn("crt.sh 查询失败，继续使用字典枚举：%v", err)
		}
		for _, name := range names {
			if len(candidates) >= maxCandidates {
				logger.Warn("候选子域名达到上限 %d，忽略剩余证书日志条目", maxCandidates)
				break
			}
			if _, exists := candidates[name]; !exists {
				candidates[name] = "crt.sh"
			}
		}
	}

	wildcardIPs := detectWildcard(ctx, domain)
	if len(wildcardIPs) > 0 {
		logger.Warn("检测到通配符 DNS：随机子域名解析到 %s，结果可能包含泛解析", strings.Join(wildcardIPs, ", "))
	}

	threads := options.Int("THREADS", 32)
	if threads < 4 {
		threads = 4
	}
	if threads > maxConcurrency {
		threads = maxConcurrency
	}

	modulekit.Section(out, "枚举配置")
	modulekit.KeyValues(out, [][2]string{
		{"根域名", domain},
		{"候选数量", fmt.Sprintf("%d", len(candidates))},
		{"并发", fmt.Sprintf("%d", threads)},
		{"通配符", boolText(len(wildcardIPs) > 0)},
	}, 60)

	found, err := resolveCandidates(ctx, candidates, threads)
	if err != nil {
		return err
	}

	sort.Slice(found, func(left int, right int) bool {
		return found[left].name < found[right].name
	})

	rows := make([][]string, 0, len(found))
	for _, item := range found {
		rows = append(rows, []string{
			item.name,
			item.source,
			modulekit.Etc(strings.Join(item.ips, ", "), 56),
		})
	}

	modulekit.Section(out, fmt.Sprintf("有效子域名 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未发现有效子域名。可提供更大的 WORDLIST 或确认 DNS 可用。")
		return nil
	}
	modulekit.Table(out, []string{"子域名", "来源", "IP"}, rows, 58)
	logger.Info("子域名枚举完成：%d 个有效结果", len(rows))
	return nil
}

/*
normalizeDomain 清理根域名输入。

参数:
  - raw (string): 原始输入。

返回:
  - string: 小写根域名。
  - error: 输入为空时返回错误。
*/
func normalizeDomain(raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	if value == "" {
		return "", fmt.Errorf("根域名不能为空")
	}
	if index := strings.Index(value, "://"); index >= 0 {
		value = value[index+3:]
	}
	if index := strings.IndexAny(value, "/?#"); index >= 0 {
		value = value[:index]
	}
	if index := strings.LastIndex(value, "@"); index >= 0 {
		value = value[index+1:]
	}
	value = strings.TrimSuffix(value, ".")
	if value == "" {
		return "", fmt.Errorf("根域名不能为空")
	}
	return value, nil
}

/*
readWordlist 从文件读取子域名字典，忽略空行与 # 注释。

参数:
  - path (string): 字典文件路径。

返回:
  - []string: 去重后的字典项。
  - error: 文件无法打开或读取失败时返回错误。
*/
func readWordlist(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开字典 %s 失败: %w", path, err)
	}
	defer file.Close()

	seen := make(map[string]struct{}, 256)
	words := make([]string, 0, 256)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.ToLower(strings.TrimSpace(scanner.Text()))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, exists := seen[line]; exists {
			continue
		}
		seen[line] = struct{}{}
		words = append(words, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("读取字典 %s 失败: %w", path, err)
	}
	return words, nil
}

/*
fetchCRTNames 从 crt.sh 证书透明日志中提取子域名。

参数:
  - ctx (context.Context): 请求上下文。
  - domain (string): 根域名。

返回:
  - []string: 去重后的子域名列表。
  - error: 请求失败、状态码异常或 JSON 解析失败时返回错误。
*/
func fetchCRTNames(ctx context.Context, domain string) ([]string, error) {
	query := url.QueryEscape("%." + domain)
	endpoint := "https://crt.sh/?q=" + query + "&output=json"

	requestCtx, cancel := context.WithTimeout(ctx, crtTimeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", "NezhaCLI/0.4")
	request.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: crtTimeout}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh 返回状态码 %d", response.StatusCode)
	}

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, crtMaxBytes))
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("解析 crt.sh 响应失败: %w", err)
	}

	seen := make(map[string]struct{}, len(entries))
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		for _, line := range strings.Split(entry.NameValue, "\n") {
			name := strings.ToLower(strings.TrimSpace(line))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || name == domain {
				continue
			}
			if !strings.HasSuffix(name, "."+domain) {
				continue
			}
			if _, exists := seen[name]; exists {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names, nil
}

/*
detectWildcard 用一个随机子域名检测泛解析。

参数:
  - ctx (context.Context): 解析上下文。
  - domain (string): 根域名。

返回:
  - []string: 泛解析返回的 IP；无泛解析时为空。
*/
func detectWildcard(ctx context.Context, domain string) []string {
	probe := fmt.Sprintf("nezha-wildcard-%d.%s", time.Now().UnixNano(), domain)
	lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupHost(lookupCtx, probe)
	if err != nil {
		return nil
	}
	return addresses
}

/*
resolveCandidates 并发解析全部候选子域名，只保留有 A/AAAA 记录的名称。

参数:
  - ctx (context.Context): 执行上下文。
  - candidates (map[string]string): 子域名到来源的映射。
  - threads (int): 并发数。

返回:
  - []resolved: 成功解析的结果。
  - error: 执行被取消时返回错误。
*/
func resolveCandidates(ctx context.Context, candidates map[string]string, threads int) ([]resolved, error) {
	type task struct {
		name   string
		source string
	}

	jobs := make(chan task, threads)
	results := make(chan resolved, threads)
	var waitGroup sync.WaitGroup

	for worker := 0; worker < threads; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for item := range jobs {
				lookupCtx, cancel := context.WithTimeout(ctx, lookupTimeout)
				addresses, err := net.DefaultResolver.LookupHost(lookupCtx, item.name)
				cancel()
				if err != nil || len(addresses) == 0 {
					continue
				}
				results <- resolved{name: item.name, source: item.source, ips: addresses}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for name, source := range candidates {
			select {
			case <-ctx.Done():
				return
			case jobs <- task{name: name, source: source}:
			}
		}
	}()

	go func() {
		waitGroup.Wait()
		close(results)
	}()

	found := make([]resolved, 0, 32)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case item, ok := <-results:
			if !ok {
				return found, nil
			}
			found = append(found, item)
		}
	}
}

/*
boolText 把布尔值转换为中文状态。

参数:
  - value (bool): 布尔值。

返回:
  - string: “是”或“否”。
*/
func boolText(value bool) string {
	if value {
		return "是"
	}
	return "否"
}
