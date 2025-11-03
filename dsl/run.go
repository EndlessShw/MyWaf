// Package dsl -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 21:58
// @Description    : 在 DSL 的 expr.Run 上做了封装
// -------------------------------------------
package dsl

import (
	"MyWaf/threat"
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
	"github.com/samber/lo"
)

// Run 在每次有 DSL 语句来时被调用
func (env *Env) Run(program *vm.Program) (any, error) {
	// 上自旋锁，保证并发安全
	env.sl.Lock()
	defer env.sl.Unlock()
	// 更新当前的威胁类型
	if env.Threat != threat.Undefined {
		env.vars["threat"] = env.Threat
	}
	// 新增一个 ALL 属性，里面存储一次请求的所有信息
	env.RequestInfo["All"] = lo.MapToSlice(env.RequestInfo, func(k string, v any) string {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
		return ""
	})
	// 更新 vars
	// todo 如果一开始存的是指针，那么这里还需要再赋值吗？而且指针的调用在 go 中也是通过 `.` 来获取的
	// point 经过测试，如果 vars 的 value 是指针，那这里就不需要进行额外的值拷贝
	//env.vars["request"] = env.RequestInfo
	// 将 vars 和 funcs 合并，一同作为 expr.Run 的启动环境
	// point go 中也有泛型
	envMaps := lo.Assign[string, any](env.vars, env.funcs)
	out, err := expr.Run(program, envMaps)
	if err != nil {
		return nil, err
	}
	return out, nil
}
