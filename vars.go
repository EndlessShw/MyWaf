// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 0:23
// @Description    : 全局变量
// -------------------------------------------
package MyWaf

var (
	// customRespHTMLTemplate 为用户传来的自定义响应体模板
	customRespHTMLTemplate string
	// respHTMLTemplate 为实际应用的 HTML 模板
	respHTMLTemplate = DefaultRespHTMLResponse
	// respStatus 为对其进行拦截处理的响应码
	respStatus = DefaultRespStatus
)
