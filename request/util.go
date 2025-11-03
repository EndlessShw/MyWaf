// Package request -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 11:00
// @Description    : 将 yaml 规则文件中的字符串转换成对应的 request.变量
// -------------------------------------------
package request

// ToMethod 将 yaml 规则文件中的 Method 字符串转换成对应的 Method 变量
// 例如 yaml 配置文件中定义 Method: GET 在代码中就会转换成 （Request.） GET
func ToMethod(s string) Method {
	method, isExist := methodMap[s]
	if !isExist {
		return UNDEFINED
	}
	return method
}

// ToElement 同上
func ToElement(s string) Element {
	element, isExist := elementMap[s]
	if !isExist {
		return Undefined
	}
	return element
}
