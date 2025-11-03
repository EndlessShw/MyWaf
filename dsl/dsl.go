// Package dsl -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 11:26
// @Description    : dsl 的环境模块
// -------------------------------------------
package dsl

import (
	"MyWaf/threat"
	"github.com/daniel-hutao/spinlock"
	"github.com/expr-lang/expr"
	"github.com/projectdiscovery/mapcidr"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"strings"
)

// Env 为 DSL 模块提供环境，一个实例对应一个 Env
type Env struct {
	// Threat 表示当前 Env 对应的威胁种类
	Threat threat.Threat

	// RequestInfo 存放一次请求的相关信息，主要包括 URI、Headers、Body、Method 和 IP 五个部分，然后还有一个 ALL
	RequestInfo map[string]any

	// funcs 是存放函数名和对应函数的 map
	funcs map[string]any

	// ------------------------------------------------------------

	// vars 存放请求变量和所有威胁类型等（包括上述部分），用于 DSL 的环境中
	vars map[string]any

	// ------------------------------------------------------------

	// opts 存放 DSL 的配置信息
	opts []expr.Option

	// sl 为自旋锁，考虑 DSL 的并发安全
	// point 引用的库：https://github.com/daniel-hutao/spinlock
	// point 参考：https://blog.csdn.net/js010111/article/details/126568547
	sl spinlock.SpinLock
}

func NewEnv() *Env {
	// 新建变量
	env := &Env{}
	// 初始化 env.vars
	env.vars = map[string]any{
		// 改名为 request 是为了方便用户通过 request.xxx 这种格式指定想要的请求信息
		"request": &env.RequestInfo,
		"threat":  &env.Threat,
	}
	// point 原来程序这里是值拷贝。使用指针的话，run 就不需要再进行赋值了，个人感觉更节省空间
	//env.vars = map[string]any{
	//	"request": env.RequestInfo,
	//	"threat":  env.Threat,
	//}
	// 将威胁种类也添加到环境中，供用户表达式使用
	for _, t := range threat.List() {
		env.vars[t.ToString()] = t
	}

	// 将一些常用的操作函数添加到 env.funcs 中
	// 初始化 env.opts
	env.funcs = map[string]any{
		// point mapcidr 是一个用于解析 IP 和 Cidr 的工具，也可以作为 lib 引用。https://github.com/projectdiscovery/mapcidr
		// cidr() 等价于 IPAddresses("IP/Cidr")，用于列出其中所有的 IP
		"cidr":        mapcidr.IPAddresses,
		"clone":       strings.Clone,
		"containsAny": strings.ContainsAny,
		"equalFold":   strings.EqualFold,
		"hasPrefix":   strings.HasPrefix,
		"hasSuffix":   strings.HasSuffix,
		"join":        strings.Join,
		"repeat":      strings.Repeat,
		"replace":     strings.Replace,
		"replaceAll":  strings.ReplaceAll,
		// point 1. Go库的标准包对向前兼容性有严格的标准。虽然 golang.org/x/... 系列包也是 Go 项目的一部分，但是在比 Go 标准包更宽松的兼容性标准下开发，一般它们支持向前兼容两个版本。
		// point 2. cases.Title 的作用是将一些 Unicode 字符转换成形状相似的常用字符。language.Und 表示转换成和原文最接近的。
		"title":       cases.Title(language.Und).String,
		"toLower":     strings.ToLower,
		"toTitle":     strings.ToTitle,
		"toUpper":     strings.ToUpper,
		"toValidUTF8": strings.ToValidUTF8,
		"trim":        strings.Trim,
		"trimLeft":    strings.TrimLeft,
		"trimPrefix":  strings.TrimPrefix,
		"trimRight":   strings.TrimRight,
		"trimSpace":   strings.TrimSpace,
		"trimSuffix":  strings.TrimSuffix,
	}

	env.opts = []expr.Option{
		expr.Env(env.vars),
		expr.Env(env.funcs),
		// 允许使用未定义的变量（不开此选项的话，使用未定义的变量就会返回 error，所以为了避免崩溃。详见：https://expr-lang.org/docs/environment
		expr.AllowUndefinedVariables(),
	}
	return env
}
