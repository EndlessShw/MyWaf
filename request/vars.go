// Package request -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 10:57
// @Description    : 对 yaml 进行多种名称适配
// -------------------------------------------
package request

var methodMap = map[string]Method{
	"GET":     GET,
	"HEAD":    HEAD,
	"POST":    POST,
	"PUT":     PUT,
	"PATCH":   PATCH,
	"DELETE":  DELETE,
	"CONNECT": CONNECT,
	"OPTIONS": OPTIONS,
	"TRACE":   TRACE,
	"ALL":     ALL,
}

var elementMap = map[string]Element{
	"uri":     URI,
	"URI":     URI,
	"headers": Headers,
	"Headers": Headers,
	"HEADERS": Headers,
	"body":    Body,
	"Body":    Body,
	"BODY":    Body,
	"any":     Any,
	"Any":     Any,
	"ANY":     Any,
}
