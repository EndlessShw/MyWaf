// Package dsl -----------------------------
// @author         : EndlessShw
// @time           : 2025/10/15 15:07
// @Description    : DSL 的工具类
// -------------------------------------------
package dsl

// GetRequestValue 从 Env（本质信息源来自当前请求）中获取请求环境
func (e *Env) GetRequestValue(key string) string {
	e.sl.Lock()
	defer e.sl.Unlock()

	value, ok := e.RequestInfo[key]
	if ok {
		return value.(string)
	}
	return ""
}
