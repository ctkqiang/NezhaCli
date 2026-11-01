// webdir 模块使用内置字典探测 Web 目录、备份文件与敏感配置。
package webdir

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/internal/modulekit"
	"github.com/ctkqiang/nezha_cli/internal/netutil"
	"github.com/ctkqiang/nezha_cli/pkg/logger"
)

const (
	// DefaultCodes 是默认视为命中的 HTTP 状态码。
	DefaultCodes = "200,204,301,302,307,308,401,403"

	// maxBodyRead 是每个响应的最大读取字节数，足以识别页面类型又不浪费流量。
	maxBodyRead = 4096

	// minThreads 与 maxThreads 限制并发请求数量。
	minThreads = 4
	maxThreads = 64

	// userAgent 是探测请求使用的标识。
	userAgent = "NezhaCLI/0.4 (+https://github.com/ctkqiang)"
)

// builtinPaths 是内置的高价值路径字典，覆盖管理后台、版本库、备份与配置泄露。
var builtinPaths = []string{
	"admin", "admin/", "admin.php", "administrator/", "admin/login", "admin/index.php",
	"login", "login.php", "logout", "register", "signup", "dashboard", "manager/html", "host-manager/html",
	"api/", "api/v1/", "api/health", "api/status", "api/v1/health", "api/v1/users", "api/v1/login", "api/v1/config",
	"graphql", "graphiql", "swagger-ui.html", "swagger-ui/", "api-docs", "v2/api-docs", "openapi.json",
	"actuator", "actuator/health", "actuator/env", "actuator/mappings", "metrics", "health", "healthz", "status", "version",
	".git/config", ".git/HEAD", ".git/", ".svn/entries", ".svn/", ".hg/", ".DS_Store",
	".env", ".env.local", ".env.dev", ".env.production", ".env.bak", ".env.example",
	"config.php", "config.php.bak", "config.json", "config.yaml", "config.yml", "appsettings.json",
	"wp-config.php", "wp-config.php.bak", "wp-login.php", "wp-admin/", "xmlrpc.php",
	"phpinfo.php", "info.php", "test.php", "shell.php", "upload/", "uploads/", "files/",
	"backup/", "backups/", "backup.zip", "backup.tar", "backup.tar.gz", "backup.tgz",
	"backup.sql", "backup.rar", "backup.7z", "www.zip", "web.zip", "site.zip", "source.zip", "src.zip", "code.zip",
	"db.sql", "database.sql", "dump.sql", "data.sql", "sql/", "db/",
	"logs/", "log/", "error.log", "access.log", "debug.log", "app.log",
	"tmp/", "temp/", "cache/", "data/", ".htaccess", ".htpasswd", "web.config", "web.config.bak",
	"robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt", "crossdomain.xml", "clientaccesspolicy.xml",
	"server-status", "server-info", "phpmyadmin/", "pma/", "myadmin/", "adminer.php", "adminer/",
	"readme.md", "README.md", "CHANGELOG.md", "LICENSE", "composer.json", "composer.lock",
	"package.json", "yarn.lock", "Dockerfile", "docker-compose.yml", ".dockerignore", "Makefile",
	"go.mod", "go.sum", "id_rsa", "id_rsa.pub", ".ssh/", ".aws/credentials", ".npmrc",
	".bash_history", ".zsh_history", "sftp-config.json", ".vscode/", ".idea/",
	".gitlab-ci.yml", ".travis.yml", "Jenkinsfile", "nginx.conf", "public/", "static/", "assets/",
}

// Module 是 Web 目录探测模块。
type Module struct{}

// probeResult 描述一个路径的探测结果。
type probeResult struct {
	path     string
	status   int
	length   int64
	location string
}

/*
New 创建 Web 目录探测模块实例。

参数:
  - 无。

返回:
  - model.Module: 模块实例。
*/
func New() model.Module {
	return &Module{}
}

/*
Meta 返回 Web 目录探测模块的元数据。

参数:
  - 无。

返回:
  - model.Meta: 模块名称、类别、说明与参数声明。
*/
func (m *Module) Meta() model.Meta {
	return model.Meta{
		Name:     "webdir",
		Aliases:  []string{"dirb", "dirsearch", "web_paths"},
		Category: modulekit.CategoryWeb,
		Summary:  "Web 目录、备份与配置泄露探测",
		Description: "使用内置字典并发请求常见管理后台、版本库、备份文件与环境配置路径。\n" +
			"不跟随重定向，只保留指定状态码，并限制单响应读取 4KB。\n" +
			"字典覆盖 admin、.git、.env、备份压缩包、Swagger、Actuator 等高频暴露面。",
		Author: modulekit.Author,
		Options: []model.Option{
			modulekit.Option("URL", "目标站点 URL，可省略 http://", true, ""),
			modulekit.Option("CODES", "视为命中的 HTTP 状态码，逗号分隔", false, DefaultCodes),
			modulekit.Option("THREADS", "并发请求数", false, "24"),
			modulekit.Option("TIMEOUT", "单次请求超时", false, "5s"),
		},
	}
}

/*
Run 对目标站点执行目录探测并输出命中路径。

参数:
  - ctx (context.Context): 请求上下文。
  - options (model.Options): 已合并默认值的模块参数。
  - out (io.Writer): 结果输出目标。

返回:
  - error: URL 非法、状态码配置错误或执行被取消时返回错误。
*/
func (m *Module) Run(ctx context.Context, options model.Options, out io.Writer) error {
	parsed, err := netutil.NormalizeURL(options.Get("URL"), "http")
	if err != nil {
		return err
	}
	if !strings.HasSuffix(parsed.Path, "/") {
		parsed.Path += "/"
	}

	codes, err := parseCodes(options.String("CODES", DefaultCodes))
	if err != nil {
		return err
	}

	threads := options.Int("THREADS", 24)
	if threads < minThreads {
		threads = minThreads
	}
	if threads > maxThreads {
		threads = maxThreads
	}
	timeout := options.Duration("TIMEOUT", 5*time.Second)

	modulekit.Section(out, "探测配置")
	modulekit.KeyValues(out, [][2]string{
		{"目标", parsed.String()},
		{"字典", fmt.Sprintf("%d 条内置路径", len(builtinPaths))},
		{"状态码", options.String("CODES", DefaultCodes)},
		{"并发", fmt.Sprintf("%d", threads)},
		{"超时", timeout.String()},
	}, 64)

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	jobs := make(chan string)
	results := make(chan probeResult, threads*2)
	var waitGroup sync.WaitGroup

	for worker := 0; worker < threads; worker++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			for path := range jobs {
				result, err := probe(ctx, client, parsed, path, codes)
				if err == nil {
					results <- result
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, path := range builtinPaths {
			select {
			case <-ctx.Done():
				return
			case jobs <- path:
			}
		}
	}()

	go func() {
		waitGroup.Wait()
		close(results)
	}()

	hits := make([]probeResult, 0, 16)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				return printHits(out, hits)
			}
			hits = append(hits, result)
		}
	}
}

/*
probe 请求单个路径并根据状态码判断是否命中。

参数:
  - ctx (context.Context): 请求上下文。
  - client (*http.Client): 已配置的 HTTP 客户端。
  - base (*url.URL): 目标站点基地址。
  - path (string): 相对路径。
  - codes (map[int]struct{}): 命中状态码集合。

返回:
  - probeResult: 命中结果。
  - error: 请求失败或状态码未命中时返回错误。
*/
func probe(ctx context.Context, client *http.Client, base *url.URL, path string, codes map[int]struct{}) (probeResult, error) {
	target := *base
	target.Path = base.Path + path
	target.RawQuery = ""
	target.Fragment = ""

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return probeResult{}, err
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "*/*")

	response, err := client.Do(request)
	if err != nil {
		return probeResult{}, err
	}
	defer response.Body.Close()

	read, _ := io.Copy(io.Discard, io.LimitReader(response.Body, maxBodyRead))
	if _, ok := codes[response.StatusCode]; !ok {
		return probeResult{}, fmt.Errorf("状态码 %d 未命中", response.StatusCode)
	}

	length := response.ContentLength
	if length < 0 {
		length = read
	}
	return probeResult{
		path:     target.RequestURI(),
		status:   response.StatusCode,
		length:   length,
		location: response.Header.Get("Location"),
	}, nil
}

/*
printHits 按状态码与路径排序并输出命中结果。

参数:
  - out (io.Writer): 结果输出目标。
  - hits ([]probeResult): 命中结果。

返回:
  - error: 始终返回 nil。
*/
func printHits(out io.Writer, hits []probeResult) error {
	sort.Slice(hits, func(left int, right int) bool {
		if hits[left].status == hits[right].status {
			return hits[left].path < hits[right].path
		}
		return hits[left].status < hits[right].status
	})

	rows := make([][]string, 0, len(hits))
	for _, hit := range hits {
		location := hit.location
		if location == "" {
			location = "-"
		}
		rows = append(rows, []string{
			strconv.Itoa(hit.status),
			modulekit.Etc(hit.path, 64),
			fmt.Sprintf("%d", hit.length),
			modulekit.Etc(location, 44),
		})
	}

	modulekit.Section(out, fmt.Sprintf("命中路径 %d", len(rows)))
	if len(rows) == 0 {
		fmt.Fprintln(out, "未发现可访问路径。可尝试调整 CODES 或提高 TIMEOUT。")
		return nil
	}
	modulekit.Table(out, []string{"状态", "路径", "长度", "跳转"}, rows, 46)
	logger.Info("Web 目录探测完成：%d 条命中", len(rows))
	return nil
}

/*
parseCodes 解析逗号分隔的 HTTP 状态码集合。

参数:
  - raw (string): 原始状态码列表。

返回:
  - map[int]struct{}: 状态码集合。
  - error: 存在非法或越界状态码时返回错误。
*/
func parseCodes(raw string) (map[int]struct{}, error) {
	codes := make(map[int]struct{}, 8)
	for _, item := range strings.Split(raw, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		code, err := strconv.Atoi(item)
		if err != nil || code < 100 || code > 599 {
			return nil, fmt.Errorf("状态码 %q 非法", item)
		}
		codes[code] = struct{}{}
	}
	if len(codes) == 0 {
		return nil, fmt.Errorf("状态码列表不能为空")
	}
	return codes, nil
}
