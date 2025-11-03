// Package request -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 10:48
// @Description    : Rules.Method 对应部分，供匹配使用
// -------------------------------------------
package request

import "net/http"

type Method string

// 对常用的 HTTP Method 进行别名，方便 Rule 规则的编写，即规则中的 request.GET 可以转换成代码中的 http.MethodGet
const (
	GET       Method = http.MethodGet
	HEAD             = http.MethodHead
	POST             = http.MethodPost
	PUT              = http.MethodPut
	PATCH            = http.MethodPatch
	DELETE           = http.MethodDelete
	CONNECT          = http.MethodConnect
	OPTIONS          = http.MethodOptions
	TRACE            = http.MethodTrace
	ALL              = "ALL"
	UNDEFINED        = ""
)
