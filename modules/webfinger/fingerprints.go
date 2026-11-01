// 指纹数据移植自 QianKunQuan 项目 internal/model/fingerprints.go。
package webfinger

// CMSFingerprint 描述一个 CMS 的识别特征。
type CMSFingerprint struct {
	Name   string
	Paths  map[string]string
	Header map[string]string
	Body   []string
	Cookie string
}

// WAFFingerprint 描述一个 WAF/CDN 的识别特征。
type WAFFingerprint struct {
	Name   string
	Header map[string]string
	Body   []string
	Cookie string
}

// CMSFingerprints 是内置的 CMS 指纹表。
var CMSFingerprints = []CMSFingerprint{
	{
		Name: "DedeCMS",
		Body: []string{"织梦内容管理系统", "/include/dedeajax2.js", "DedeCMS", "power by dedecms", "desk_dede.ico", "/templets/default/images/dedecms.css"},
	},
	{
		Name:   "ThinkPHP",
		Header: map[string]string{"X-Powered-By": "ThinkPHP"},
		Body:   []string{"ThinkPHP", "thinkphp", "var ThinkPHP =", "ThinkPHP.Version", "_404.png"},
	},
	{
		Name:  "WordPress",
		Paths: map[string]string{"/wp-login.php": "wordpress", "/readme.html": "wordpress"},
		Body:  []string{"WordPress", "wp-content", "wp-includes", "wp-admin", `meta name="generator" content="WordPress`},
	},
	{
		Name: "Discuz!",
		Body: []string{"Discuz!", "Comsenz", "discuz", "template/default/common/common.css", "source/plugin", "uc_server", "favicon_discuz.ico"},
	},
	{
		Name: "PHPCMS",
		Body: []string{"PHPCMS", "phpcms", "statics/js/html5shiv.min.js", "index.php?m=member", "phpcms/modules"},
	},
	{
		Name: "ECShop",
		Body: []string{"ECSHOP", "ecshop", "powered by ecshop", "themes/default/images/common.css", "data/config.php"},
	},
	{
		Name: "MetInfo",
		Body: []string{"metinfo", "MetInfo", "metinfo.cn", "app/met", "public/images/metinfo.png"},
	},
	{
		Name:  "Joomla!",
		Paths: map[string]string{"/administrator/": "joomla", "/readme.txt": "joomla"},
		Body:  []string{"Joomla!", "joomla", "Joomla -", "media/system/js/core.js", "templates/system/css/system.css"},
	},
	{
		Name:  "Drupal",
		Paths: map[string]string{"/misc/drupal.js": "drupal", "/readme.txt": "drupal"},
		Body:  []string{"Drupal", "drupal", "misc/drupal.js", "themes/bartik", "sites/all/modules"},
	},
	{
		Name: "Typecho",
		Body: []string{"Typecho", "typecho", "usr/themes", "var/Widget", "install.php"},
	},
	{
		Name: "emlog",
		Body: []string{"emlog", "Emlog", "content/templates", "include/lib/", "emlog.net"},
	},
	{
		Name: "Z-Blog",
		Body: []string{"Z-Blog", "ZBlog", "zblog", "zb_system", "zb_users"},
	},
	{
		Name: "FineCMS",
		Body: []string{"FineCMS", "finecms", "dayrui", "index.php?c=api", "statics/asset/"},
	},
	{
		Name: "PbootCMS",
		Body: []string{"PbootCMS", "pbootcms", "static/pbootcms", "apps/home/controller", "Powered by PbootCMS"},
	},
	{
		Name: "RuoYi",
		Body: []string{"若依", "RuoYi", "ruoyi", "ruoyi-ui", "ruoyi-vue", "ruoyi-admin"},
	},
	{
		Name: "JEECG",
		Body: []string{"JEECG", "jeecg", "jeecg-boot", "org.jeecg"},
	},
	{
		Name: "Fiora",
		Body: []string{"Fiora", "fiora"},
	},
	{
		Name:   "Tomcat",
		Header: map[string]string{"Server": "Apache-Coyote"},
		Body:   []string{"Apache Tomcat", "tomcat.png", "CATALINA_HOME", "Tomcat WebSocket", "Tomcat Manager"},
	},
	{
		Name:   "Nginx",
		Header: map[string]string{"Server": "nginx"},
		Body:   []string{"nginx", "Welcome to nginx"},
	},
	{
		Name:   "Apache",
		Header: map[string]string{"Server": "Apache"},
		Body:   []string{"Apache/2", "This is the default welcome page", "If you can read this page"},
	},
	{
		Name:   "IIS",
		Header: map[string]string{"Server": "Microsoft-IIS"},
		Body:   []string{"IIS", "Internet Information Services", "ASP.NET", "Server Error in Application"},
	},
}

// WAFFingerprints 是内置的 WAF/CDN 指纹表。
var WAFFingerprints = []WAFFingerprint{
	{
		Name: "安全狗",
		Body: []string{"safedog", "safedog.cn", "安全狗", "siteintercept", "furl.safedog.cn"},
	},
	{
		Name:   "阿里云盾",
		Header: map[string]string{"Ali-Swift-Global": ""},
		Body:   []string{"aliyundun", "aliyun.com", "云盾", "aliyun.waf", "error.aliyun.com"},
	},
	{
		Name:   "腾讯云WAF",
		Header: map[string]string{"X-Use-Svr": "Sec"},
		Body:   []string{"waf.tencent-cloud.com", "qcloud", "tencent-cloud"},
	},
	{
		Name:   "百度云加速",
		Header: map[string]string{"Yjs-Id": ""},
		Body:   []string{"yunjiasu", "baidu.com", "百度云加速"},
	},
	{
		Name:   "CloudFlare",
		Header: map[string]string{"Server": "cloudflare", "CF-RAY": ""},
		Body:   []string{"cloudflare", "Attention Required! | Cloudflare", "cf-ray", "Cloudflare Ray ID", "challenges.cloudflare.com"},
	},
	{
		Name:   "ModSecurity",
		Header: map[string]string{"Server": "Mod_Security"},
		Body:   []string{"ModSecurity", "mod_security", "NOYB", "modsec"},
	},
	{
		Name:   "阿里云CDN",
		Header: map[string]string{"X-Swift-Cache": ""},
		Body:   []string{},
	},
	{
		Name:   "Incapsula/Imperva",
		Header: map[string]string{"X-CDN": "Incapsula", "X-Iinfo": ""},
		Body:   []string{"incapsula", "Imperva", "distil", "incap_ses", "/_Incapsula_Resource"},
	},
	{
		Name:   "Akamai",
		Header: map[string]string{"Server": "AkamaiGHost", "Akamai-Origin-Hop": ""},
		Body:   []string{"akamai", "Akamai", "Reference #"},
	},
	{
		Name: "宝塔WAF",
		Body: []string{"宝塔防火墙", "bt.cn", "baota", "宝塔面板"},
	},
	{
		Name:   "360网站卫士",
		Header: map[string]string{"X-Powered-By-360WZB": "wangzhanbao"},
		Body:   []string{"360网站卫士", "360wzb", "wangzhanbao"},
	},
	{
		Name:   "知道创宇加速乐",
		Header: map[string]string{"X-Powered-By-Anquanbao": ""},
		Body:   []string{"jiasule", "加速乐", "anquanbao", "knownsec", "知道创宇"},
	},
	{
		Name:   "网宿WAF",
		Header: map[string]string{"WS-Request-Id": ""},
		Body:   []string{"wangsu", "网宿", "wscdns.com"},
	},
	{
		Name:   "华为云WAF",
		Header: map[string]string{"HWCDN-WAF": ""},
		Body:   []string{"huaweicloud", "华为云", "hwclouds"},
	},
}

// cmsVersionPatterns 是 CMS 版本号的正则模板（区分大小写不敏感）。
var cmsVersionPatterns = map[string][]string{
	"WordPress": {`(?i)wordpress\s+(\d+\.\d+(\.\d+)?)`, `(?i)content="WordPress\s+(\d+\.\d+(\.\d+)?)"`},
	"DedeCMS":   {`(?i)dedecms\s*v?(\d+\.\d+(\.\d+)?)`, `(?i)织梦内容管理系统\s*v?(\d+\.\d+)`},
	"Discuz!":   {`(?i)discuz!?(?:\s*X)?\s*(\d+\.\d+(\.\d+)?)`},
	"Joomla!":   {`(?i)joomla!\s*(\d+\.\d+(\.\d+)?)`},
	"Drupal":    {`(?i)drupal\s*(\d+\.\d+(\.\d+)?)`},
	"Typecho":   {`(?i)typecho\s*(\d+\.\d+(\.\d+)?)`},
	"ThinkPHP":  {`(?i)thinkphp\s*(\d+\.\d+(\.\d+)?)`},
	"Tomcat":    {`(?i)apache\s+tomcat\s*/?\s*(\d+\.\d+(\.\d+)?)`},
	"Nginx":     {`(?i)nginx/(\d+\.\d+(\.\d+)?)`},
	"Apache":    {`(?i)apache/(\d+\.\d+(\.\d+)?)`},
	"IIS":       {`(?i)microsoft-iis/(\d+\.\d+)`},
}
