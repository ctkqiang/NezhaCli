// MITRE ATT&CK 技术目录移植自 vecmap 项目 internal/constant/mitre.go。
// 仅收录 CVE 关联与报告层需要用到的技术条目，URL 按官方模式生成。
package vecmap

import "strings"

// MITRETechnique 描述一条 MITRE ATT&CK 技术。
type MITRETechnique struct {
	ID       string
	Name     string
	NameZH   string
	Tactic   string
	TacticZH string
	URL      string
}

// mitreCatalog 保存内置的 ATT&CK 技术条目。
var mitreCatalog = map[string]MITRETechnique{
	"T1190": {ID: "T1190", Name: "Exploit Public-Facing Application", NameZH: "利用面向公众的应用", Tactic: "Initial Access", TacticZH: "初始访问"},
	"T1078": {ID: "T1078", Name: "Valid Accounts", NameZH: "有效账户", Tactic: "Initial Access", TacticZH: "初始访问"},
	"T1005": {ID: "T1005", Name: "Data from Local System", NameZH: "本地系统数据", Tactic: "Collection", TacticZH: "收集"},
	"T1213": {ID: "T1213", Name: "Data from Information Repositories", NameZH: "信息库数据", Tactic: "Collection", TacticZH: "收集"},
	"T1046": {ID: "T1046", Name: "Network Service Discovery", NameZH: "网络服务发现", Tactic: "Discovery", TacticZH: "发现"},
	"T1083": {ID: "T1083", Name: "File and Directory Discovery", NameZH: "文件与目录发现", Tactic: "Discovery", TacticZH: "发现"},
	"T1595": {ID: "T1595", Name: "Active Scanning", NameZH: "主动扫描", Tactic: "Reconnaissance", TacticZH: "侦察"},
	"T1590": {ID: "T1590", Name: "Gather Victim Network Information", NameZH: "收集受害网络信息", Tactic: "Reconnaissance", TacticZH: "侦察"},
	"T1592": {ID: "T1592", Name: "Gather Victim Host Information", NameZH: "收集受害主机信息", Tactic: "Reconnaissance", TacticZH: "侦察"},
	"T1589": {ID: "T1589", Name: "Gather Victim Identity Information", NameZH: "收集受害身份信息", Tactic: "Reconnaissance", TacticZH: "侦察"},
	"T1203": {ID: "T1203", Name: "Exploitation for Client Execution", NameZH: "客户端执行利用", Tactic: "Execution", TacticZH: "执行"},
	"T1530": {ID: "T1530", Name: "Data from Cloud Storage", NameZH: "云存储数据", Tactic: "Collection", TacticZH: "收集"},
	"T1090": {ID: "T1090", Name: "Proxy", NameZH: "代理", Tactic: "Command and Control", TacticZH: "命令与控制"},
	"T1189": {ID: "T1189", Name: "Drive-by Compromise", NameZH: "路过式攻击", Tactic: "Initial Access", TacticZH: "初始访问"},
	"T1552": {ID: "T1552", Name: "Unsecured Credentials", NameZH: "未保护的凭据", Tactic: "Credential Access", TacticZH: "凭据访问"},
	"T1110": {ID: "T1110", Name: "Brute Force", NameZH: "暴力破解", Tactic: "Credential Access", TacticZH: "凭据访问"},
	"T1059": {ID: "T1059", Name: "Command and Scripting Interpreter", NameZH: "命令与脚本解释器", Tactic: "Execution", TacticZH: "执行"},
}

/*
LookupMITRE 按技术编号查找内置目录。

参数:
  - id (string): 技术编号，例如 "T1190"。

返回:
  - MITRETechnique: 匹配的技术条目。
  - bool: 是否存在该条目。
*/
func LookupMITRE(id string) (MITRETechnique, bool) {
	technique, ok := mitreCatalog[strings.TrimSpace(id)]
	return technique, ok
}

/*
MitreURL 生成官方技术页面 URL。

参数:
  - id (string): 技术编号。

返回:
  - string: 官方页面地址。
*/
func MitreURL(id string) string {
	base := "https://attack.mitre.org/techniques/"
	index := strings.Index(id, ".")
	if index < 0 {
		return base + id + "/"
	}
	return base + id[:index] + "/" + id[index+1:] + "/"
}
