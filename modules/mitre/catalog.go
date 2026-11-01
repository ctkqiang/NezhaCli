// 战术与技术目录数据移植自 MITRERedTeam 项目 catalog/tactics.json 与 catalog/techniques.json。
// BBxx 编号为主键，MITRE ATT&CK ID 仅作对齐元数据；新增内容无需改代码，直接追加切片即可。
package mitre

// Tactic 描述一条评估战术。
type Tactic struct {
	ID          string
	Name        string
	Description string
}

// Technique 描述一条评估技术。
type Technique struct {
	ID          string
	Name        string
	Tactic      string
	Description string
	Executor    string
	Mode        string
	Tools       []string
	MITRE       []string
}

// Tactics 是内置的 25 条战术目录。
var Tactics = []Tactic{
	{ID: "BB01", Name: "侦察", Description: "发现目标及其组织的公开可观察信息。"},
	{ID: "BB02", Name: "攻击面发现", Description: "识别可访问的主机、服务、应用程序及暴露的接口。"},
	{ID: "BB03", Name: "DNS 与域名分析", Description: "分析 DNS 基础设施、域名关系及 DNS 安全配置。"},
	{ID: "BB04", Name: "网络与服务枚举", Description: "识别暴露的网络服务并分析其配置特征。"},
	{ID: "BB05", Name: "Web 应用枚举", Description: "发现 Web 应用的路由、资源、参数和接口。"},
	{ID: "BB06", Name: "API 枚举", Description: "发现并分析 REST、GraphQL 及其他 API 接口。"},
	{ID: "BB07", Name: "认证", Description: "评估认证、身份验证与账户恢复机制。"},
	{ID: "BB08", Name: "授权与访问控制", Description: "评估授权边界、对象所有权与权限分离。"},
	{ID: "BB09", Name: "会话管理", Description: "评估会话生命周期、Cookie 与令牌处理。"},
	{ID: "BB10", Name: "注入", Description: "评估应用输入处理中的注入漏洞。"},
	{ID: "BB11", Name: "客户端安全", Description: "评估浏览器端应用的安全控制及客户端攻击面。"},
	{ID: "BB12", Name: "服务端请求处理", Description: "评估服务端对 URL、回调及外部资源的处理。"},
	{ID: "BB13", Name: "文件与资源处理", Description: "评估文件上传、下载、路径处理及资源处理。"},
	{ID: "BB14", Name: "业务逻辑", Description: "评估应用工作流、状态转换、事务与业务规则。"},
	{ID: "BB15", Name: "API 安全", Description: "评估 API 授权、对象处理、速率限制及协议相关安全。"},
	{ID: "BB16", Name: "配置与部署", Description: "识别与安全相关的配置及部署弱点。"},
	{ID: "BB17", Name: "信息泄露", Description: "识别应用或基础设施敏感信息的非预期泄露。"},
	{ID: "BB18", Name: "云与存储", Description: "评估云资源、对象存储、无服务器服务及云暴露面。"},
	{ID: "BB19", Name: "依赖与组件安全", Description: "识别存在漏洞、过时或暴露的软件组件。"},
	{ID: "BB20", Name: "密码与传输安全", Description: "评估 TLS、证书、密码学及敏感数据传输控制。"},
	{ID: "BB21", Name: "基础设施安全", Description: "评估暴露的基础设施服务与管理接口。"},
	{ID: "BB22", Name: "漏洞检测", Description: "识别已知漏洞及安全相关条件。"},
	{ID: "BB23", Name: "验证与影响评估", Description: "验证发现、评估影响并减少误报。"},
	{ID: "BB24", Name: "攻击路径与漏洞利用链", Description: "关联各项发现并识别多步安全影响。"},
	{ID: "BB25", Name: "证据与报告", Description: "收集、关联并导出可复现的安全发现。"},
}

// Techniques 是内置的 27 条技术目录。
var Techniques = []Technique{
	{ID: "BB01.001", Name: "组织信息发现", Tactic: "BB01", Description: "识别与目标组织相关的公开可观察信息。", Executor: "organization-discovery", Mode: "passive", MITRE: []string{"T1589"}},
	{ID: "BB01.002", Name: "域名发现", Tactic: "BB01", Description: "识别与授权目标相关的域名。", Executor: "domain-discovery", Mode: "passive", Tools: []string{"whois"}, MITRE: []string{"T1589.001"}},
	{ID: "BB01.003", Name: "子域名枚举", Tactic: "BB01", Description: "识别与授权目标相关的子域名。", Executor: "subdomain-enumeration", Mode: "passive", Tools: []string{"subfinder"}, MITRE: []string{"T1595"}},
	{ID: "BB01.004", Name: "证书透明度枚举", Tactic: "BB01", Description: "通过证书透明度数据识别与目标相关的主机名。", Executor: "certificate-transparency", Mode: "passive", Tools: []string{"crtsh"}, MITRE: []string{"T1596.003"}},
	{ID: "BB01.005", Name: "ASN 枚举", Tactic: "BB01", Description: "识别与授权目标相关的自治系统信息。", Executor: "asn-enumeration", Mode: "passive", MITRE: []string{"T1590.005"}},
	{ID: "BB01.006", Name: "IP 段发现", Tactic: "BB01", Description: "识别与授权目标相关的 IP 段。", Executor: "ip-range-discovery", Mode: "passive", MITRE: []string{"T1590.005"}},
	{ID: "BB01.007", Name: "WHOIS 枚举", Tactic: "BB01", Description: "收集与授权目标相关的注册信息。", Executor: "whois-enumeration", Mode: "passive", Tools: []string{"whois"}, MITRE: []string{"T1596.002"}},
	{ID: "BB01.008", Name: "DNS 枚举", Tactic: "BB01", Description: "枚举与授权目标相关的 DNS 记录。", Executor: "dns-enumeration", Mode: "passive", Tools: []string{"dig"}, MITRE: []string{"T1590.002"}},
	{ID: "BB01.009", Name: "反向 DNS 枚举", Tactic: "BB01", Description: "识别与已发现 IP 地址相关的主机名。", Executor: "reverse-dns", Mode: "passive", Tools: []string{"dig"}, MITRE: []string{"T1590.002"}},
	{ID: "BB01.010", Name: "历史 DNS 发现", Tactic: "BB01", Description: "识别与目标相关的历史 DNS 关系。", Executor: "historical-dns", Mode: "passive", MITRE: []string{"T1596.002"}},
	{ID: "BB02.001", Name: "存活主机发现", Tactic: "BB02", Description: "识别授权目标范围内可访问的主机。", Executor: "live-host-discovery", Mode: "active", Tools: []string{"httpx"}, MITRE: []string{"T1595"}},
	{ID: "BB02.005", Name: "端口发现", Tactic: "BB02", Description: "识别授权目标范围内暴露的网络端口。", Executor: "port-discovery", Mode: "active", Tools: []string{"nmap"}, MITRE: []string{"T1046"}},
	{ID: "BB05.001", Name: "目录枚举", Tactic: "BB05", Description: "识别授权 Web 目标中可访问的目录和资源。", Executor: "directory-enumeration", Mode: "active", Tools: []string{"ffuf"}, MITRE: []string{"T1083"}},
	{ID: "BB05.003", Name: "端点发现", Tactic: "BB05", Description: "识别授权 Web 目标中的应用端点。", Executor: "endpoint-discovery", Mode: "active", Tools: []string{"ffuf", "httpx"}, MITRE: []string{"T1046"}},
	{ID: "BB07.001", Name: "登录流程分析", Tactic: "BB07", Description: "评估应用的认证流程与安全边界。", Executor: "login-flow-analysis", Mode: "manual"},
	{ID: "BB08.001", Name: "IDOR 测试", Tactic: "BB08", Description: "评估对象引用是否可在授权安全上下文之外被访问。", Executor: "idor", Mode: "manual"},
	{ID: "BB10.001", Name: "SQL 注入", Tactic: "BB10", Description: "评估授权应用输入中的 SQL 注入漏洞。", Executor: "sql-injection", Mode: "active", Tools: []string{"sqlmap"}, MITRE: []string{"T1190"}},
	{ID: "BB11.001", Name: "反射型 XSS", Tactic: "BB11", Description: "评估授权应用的输入与响应中是否存在反射型跨站脚本。", Executor: "reflected-xss", Mode: "active", Tools: []string{"nuclei"}, MITRE: []string{"T1189"}},
	{ID: "BB12.001", Name: "SSRF 发现", Tactic: "BB12", Description: "评估授权服务端 URL 处理中是否存在请求伪造条件。", Executor: "ssrf", Mode: "active", MITRE: []string{"T1090"}},
	{ID: "BB13.001", Name: "路径遍历", Tactic: "BB13", Description: "评估授权文件与资源路径中的遍历弱点。", Executor: "path-traversal", Mode: "active", Tools: []string{"nuclei"}, MITRE: []string{"T1083"}},
	{ID: "BB14.001", Name: "工作流绕过", Tactic: "BB14", Description: "评估应用必需的工作流步骤是否可以被绕过。", Executor: "workflow-bypass", Mode: "manual"},
	{ID: "BB14.003", Name: "竞态条件测试", Tactic: "BB14", Description: "评估授权状态变更操作中的并发弱点。", Executor: "race-condition", Mode: "active"},
	{ID: "BB15.005", Name: "批量赋值", Tactic: "BB15", Description: "评估 API 对象属性是否可在预期授权边界之外被修改。", Executor: "mass-assignment", Mode: "manual"},
	{ID: "BB16.011", Name: "Git 仓库泄露", Tactic: "BB16", Description: "检测授权 Web 目标上暴露的 Git 仓库元数据。", Executor: "git-exposure", Mode: "active", Tools: []string{"nuclei"}, MITRE: []string{"T1213"}},
	{ID: "BB17.002", Name: "敏感信息泄露", Tactic: "BB17", Description: "识别意外暴露的凭证、API 密钥或其他敏感信息。", Executor: "secret-discovery", Mode: "passive", MITRE: []string{"T1552"}},
	{ID: "BB18.002", Name: "公共存储桶检测", Tactic: "BB18", Description: "识别授权范围内可公开访问的云存储资源。", Executor: "public-bucket-detection", Mode: "active", MITRE: []string{"T1530"}},
	{ID: "BB22.001", Name: "已知 CVE 检测", Tactic: "BB22", Description: "识别影响已发现授权组件的已知漏洞。", Executor: "cve-detection", Mode: "active", Tools: []string{"nuclei"}, MITRE: []string{"T1203"}},
}
