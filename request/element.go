// Package request -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 10:34
// @Description    : Rules.Element 指定的部分，其中 Method 类型过多，因此单独分开
// -------------------------------------------
package request

type Element int8

const (
	Undefined Element = iota - 1

	// URI 指的是待匹配的 URI（路径和请求参数）
	URI

	Headers

	Body

	Any
)
