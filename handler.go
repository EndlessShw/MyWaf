// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/18 14:50
// @Description    : 定义了“用于处理拦截”的 handler
// -------------------------------------------
package MyWaf

import (
	"github.com/valyala/fasttemplate"
	"net/http"
)

// defaultRejectHandler 是默认的拦截 Handler，上层可以通过 setRejectHandler 来覆盖默认的
func defaultRejectHandler(w http.ResponseWriter, r *http.Request) {
	// 设置响应头的 Content-Type 为 text/html
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 设置响应码为 403
	w.WriteHeader(http.StatusBadRequest)
	// 获取分析请求时的一些数据，部分用于返回体
	respData := map[string]any{
		"ID":      w.Header().Get(xMyWafReqId),
		"message": w.Header().Get(XMyWafMsg),
		"threat":  w.Header().Get(xMyWafThreatType),
	}
	// 如果用户指定了 403 的 HTML，那么就使用用户的。
	if customRespHTMLTemplate != "" {
		respHTMLTemplate = customRespHTMLTemplate
	}
	// 解析相应模板并返回
	// note 这里确保默认模板没有问题，因此改用 fasttemplate.NewTemplate 而不是 fasttemplate.New
	template, _ := fasttemplate.NewTemplate(respHTMLTemplate, "{{", "}}")
	_, _ = template.Execute(w, respData)
}

// SetHandler 设置拒绝 Handler
func (mywaf *MyWaf) SetHandler(handler http.Handler) {
	mywaf.rejectHandler = handler
}

// Handler 继承并返回 http.HandlerFunc，其中添加分析的功能
// 传入的 normalHandler 为正常业务的 Handler
func (mywaf *MyWaf) Handler(normalHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		threatType, err := mywaf.analyzeRequest(w, r)
		if err != nil {
			mywaf.postAnalyze(w, r, err, threatType)
			return
		}
		// 如果没有拦截的话，就放行
		normalHandler.ServeHTTP(w, r)
	})
}

// todo 针对不同的 Web 架构做适配
