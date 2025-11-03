// Package option -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 23:08
// @Description    : 一条规则的内部具体细节，从多个方面确定生效的具体方式
// -------------------------------------------
package option

import (
	"MyWaf/request"
	"github.com/dwisiswant0/pcregexp/pkg/regexp"
	"github.com/expr-lang/expr/vm"
)

// Detail 之间的逻辑是 Or，只要一条 Rule 中的 Detail 命中一个，那就相当于命中的该 Rule
type Detail struct {
	// Method 表示 HTTP 的请求方式，是 string 的别名
	// 当 DSL 指定时，该项会被忽略
	Method request.Method `json:"method" yaml:"method"`

	// Element 表示一个请求的元素/部分以供匹配，主要分为 URI、Headers、Body 和 Any。具体为 int 的别名。
	// - `0` 代表 [request.URI]
	// - `1` 代表 [request.Headers]
	// - `2` 代表 [request.Body]
	// - `3` 代表 [request.Any]
	// 当 DSL 指定时，该项会被忽略
	Element request.Element `json:"element" yaml:"element"`

	// RegPattern 表示匹配的正则表达式
	// 当 DSL 指定时，该项会被忽略
	RegPattern string `json:"regPattern" yaml:"regPattern"`

	// RegExp 为 RegPattern 编译后的正则，不在配置文件中指定
	RegExp *regexp.Regexp

	// note 如果 DSL 设置了，以上设置的部分都会被忽略 -----------------------

	// DSL 是针对请求的 DSL 匹配表达式
	// note DSL 和 RegPattern 不能同时为空
	DSL string `json:"dsl" yaml:"dsl"`

	// DslProgram 为 DSL 编译后的表达式，不在配置文件中指定
	DslProgram *vm.Program
}
