// Package option -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 15:20
// @Description    : 控制类
// -------------------------------------------
package option

import (
	"github.com/EndlessShw/MyWaf/threat"
	"io"
)

type Options struct {
	// Excludes 表示哪种攻击类型不检测。攻击类型定义在 threat.Threat
	// 在 YAML 或 JSON 文件中，可以用以下 int 来对应类型：
	// - `0` 代表 [Threat.Custom] 自定义类型
	// - `1` 代表 [Threat.CommonWebAttack] 通用 Web 攻击
	// - `2` 代表 [Threat.CVE] CVE
	// - `3` 代表 [Threat.BadIPAddress] 恶意 IP 检测
	// - `4` 代表 [Threat.BadReferrer] 恶意 Referrer
	// - `5` 代表 [Threat.BadCrawler] 恶意爬虫
	// - `6` 代表 [Threat.DirectoryBruteforce] 恶意目录爆破
	// - `7` 代表 [Threat.MaliciousCommand] 恶意命令执行
	Excludes []threat.Threat `json:"excludes" yaml:"excludes"`

	// Whitelists 一个 DSL 表达式 list
	Whitelists []string `json:"whitelists" yaml:"whitelists"`

	// Customs 为用户额外添加的规则，为 Rule 的 list，对请求运用安全规则。
	Customs []Rule `json:"customs" yaml:"customs"`

	// CustomsFromFile 表示存放用户规则文件的地址，路径中支持 `*` 通配符。
	CustomsFromFile string `json:"customs_from_file" yaml:"customs_from_file"`

	// Response 指定某个响应码时应该返回的 HTML，默认为 403。同时也有默认响应模板
	Response Response `json:"response" yaml:"response"`

	// LogFile 表示日志写入的路径。
	// 如果该选项被指定，那么标准错误输入 stderr 也会写入该文件（前提是 NoStderr 是 false）
	LogFile string `json:"log_file" yaml:"log_file"`

	// LogWrite 是 io.Writer 的接口，用户通过它可以指定日志的写入方式。
	// TODO 这里理解还不是很透彻，等具体结合业务代码再分析
	// 默认情况下是通过 stderr（前提是 NoStderr 是 false），然而，只要用户继承了 io.Writer，那么就可以自定义日志的写入目的地。
	// 当该选项被指定时，日志都会写入 LogFile 和 stderr 的地方。用户可以将日志写入远程日志服务、存到数据库或者其他特殊的方式。
	LogWrite io.Writer `json:"-" yaml:"-"`

	// TODO: 一天对应一个日志文件
	// LogRotate specifies whether to rotate the log file when it reaches a new day.
	// LogRotate bool

	// NoStderr 指定是否将日志写入到 stderr 流。
	// 当设置为 true 时，日志不再写入 stderr 流。默认是写入到 stderr 流（false）
	NoStderr bool `json:"no_stderr" yaml:"no_stderr"`

	// NoUpdateCheck 表示是否关闭威胁库的自动更新
	// 如果 InMemory 选项设置为 true，那么该选项将会失效，容器内的数据库将会一直自动更新。
	NoUpdateCheck bool `json:"no_update_check" yaml:"no_update_check"`

	// NoReqCache 表示是否将请求进行缓存
	NoReqCache bool `json:"no_req_cache" yaml:"no_req_cache"`

	// InMemory 决定是否在初始化阶段时，将威胁数据库加载到内存中
	// 在 distroless 或者 runtime 镜像（也就是 docker）中，当该值设置为 true 时，威胁数据库将会加载到内存（Map 变量）中。
	// （在虚拟环境下，直接访问文件可能会受限或缓慢，处于这种情况考虑给出该选项）
	// 如果设置为 false，首次启动时，威胁数据库将会下载并且存放在用户下的 cache 目录（~/.cache/）。后续的启动将会使用 cache 下的数据库
	InMemory bool `json:"in_memory" yaml:"in_memory"`

	// FalcosidekickURL 指定 Falco 服务开启的地址。
	// Falco 为云环境下使用的 Runtime 安全检测引擎，Falcosidekick 用于处理 Falco 事件并可以将结果输出到某些平台。
	// MyWaf 借用 Falcosidekick 作为事件暂存平台，用户可以通过 Falcosidekick 来将事件输出到某些平台上（和 Falco 并列）
	FalcosidekickURL string `json:"falcosidekick_url" yaml:"falcosidekick_url"`

	// Verbose 表示日志的记录是否是详细的。如果设置为 true，那么日志将会记录更为详细的内容。
	Verbose bool `json:"verbose" yaml:"verbose"`
}
