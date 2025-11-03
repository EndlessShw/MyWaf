// Package option -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 23:31
// @Description    : 当请求被阻断或拒绝时，配置响应的内容
// -------------------------------------------
package option

type Response struct {
	// Status 为响应码，当一个请求的响应码为其时，响应体应该返回 HTML 模板。默认是 MyWaf.DefaultRespStatus
	Status int `json:"status" yaml:"status"`

	// HTML 就是响应体应该返回的 HTML 代码
	HTML string `json:"html" yaml:"html"`

	// HTMLFile 就是 HTML 的路径
	HTMLFile string `json:"html_file" yaml:"html_file"`
}
