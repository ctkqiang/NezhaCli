package core

import (
	"fmt"

	"github.com/ctkqiang/nezha_cli/internal/model"
	"github.com/ctkqiang/nezha_cli/modules/bt"
	"github.com/ctkqiang/nezha_cli/modules/connect"
	"github.com/ctkqiang/nezha_cli/modules/crunch"
	"github.com/ctkqiang/nezha_cli/modules/cve"
	"github.com/ctkqiang/nezha_cli/modules/cve_2025_14847"
	"github.com/ctkqiang/nezha_cli/modules/cve_2025_4334"
	"github.com/ctkqiang/nezha_cli/modules/cve_2025_66478"
	"github.com/ctkqiang/nezha_cli/modules/dns"
	"github.com/ctkqiang/nezha_cli/modules/encode"
	"github.com/ctkqiang/nezha_cli/modules/esp"
	"github.com/ctkqiang/nezha_cli/modules/hash"
	"github.com/ctkqiang/nezha_cli/modules/http"
	"github.com/ctkqiang/nezha_cli/modules/lan"
	"github.com/ctkqiang/nezha_cli/modules/mitre"
	"github.com/ctkqiang/nezha_cli/modules/payloads"
	"github.com/ctkqiang/nezha_cli/modules/portscan"
	"github.com/ctkqiang/nezha_cli/modules/random"
	"github.com/ctkqiang/nezha_cli/modules/service"
	"github.com/ctkqiang/nezha_cli/modules/subdomain"
	"github.com/ctkqiang/nezha_cli/modules/sysinfo"
	"github.com/ctkqiang/nezha_cli/modules/tls"
	"github.com/ctkqiang/nezha_cli/modules/vecmap"
	"github.com/ctkqiang/nezha_cli/modules/web"
	"github.com/ctkqiang/nezha_cli/modules/webdir"
	"github.com/ctkqiang/nezha_cli/modules/webfinger"
	"github.com/ctkqiang/nezha_cli/modules/whois"
	"github.com/ctkqiang/nezha_cli/modules/wifi_brute"
	"github.com/ctkqiang/nezha_cli/modules/wifi_clone"
	"github.com/ctkqiang/nezha_cli/modules/wifi_deauth"
	"github.com/ctkqiang/nezha_cli/modules/wifi_list"
	"github.com/ctkqiang/nezha_cli/modules/wifi_scan"
)

/*
LoadNative 注册全部内置模块并返回注册表。
内置模块全部为纯 Go 实现，不依赖外部二进制、Root 或 raw socket。

参数:
  - 无。

返回:
  - *Registry: 已注册全部内置模块的注册表。
  - error: 模块名称或别名冲突时返回错误。
*/
func LoadNative() (*Registry, error) {
	native := []model.Module{
		portscan.New(),
		service.New(),
		dns.New(),
		whois.New(),
		subdomain.New(),
		lan.New(),
		web.New(),
		tls.New(),
		webdir.New(),
		webfinger.New(),
		payloads.New(),
		vecmap.New(),
		mitre.New(),
		cve.New(),
		cve_2025_14847.New(),
		cve_2025_4334.New(),
		cve_2025_66478.New(),
		connect.New(),
		http.New(),
		hash.New(),
		encode.New(),
		random.New(),
		crunch.New(),
		esp.New(),
		wifi_list.New(),
		wifi_scan.New(),
		wifi_deauth.New(),
		wifi_brute.New(),
		wifi_clone.New(),
		bt.New(),
		sysinfo.New(),
	}

	registry := NewRegistry()
	for _, module := range native {
		if err := registry.Register(module); err != nil {
			return nil, fmt.Errorf("注册内置模块失败: %w", err)
		}
	}
	return registry, nil
}

/*
Load 加载内置模块与指定目录下的 SanTaiZi 兼容外部模块。
外部模块加载失败只产生警告，不会阻止控制台启动。

参数:
  - externalDir (string): 外部模块目录；为空时使用 modules/bin。

返回:
  - *Registry: 合并后的模块注册表。
  - []error: 外部模块加载警告。
  - error: 内置模块注册失败时返回错误。
*/
func Load(externalDir string) (*Registry, []error, error) {
	registry, err := LoadNative()
	if err != nil {
		return nil, nil, err
	}
	if externalDir == "" {
		externalDir = DefaultExternalDir
	}

	externals, warnings := LoadExternal(externalDir)
	for _, external := range externals {
		if err := registry.Register(external); err != nil {
			warnings = append(warnings, err)
		}
	}
	return registry, warnings, nil
}
