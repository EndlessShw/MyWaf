// Package dsl -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 17:46
// @Description    :
// -------------------------------------------
package dsl

import (
	"github.com/expr-lang/expr"
	"github.com/expr-lang/expr/vm"
)

// Compile 将上层用户传来的逻辑表达式执行，返回结果待 expr.Run
func (env *Env) Compile(code string) (*vm.Program, error) {
	program, err := expr.Compile(code, env.opts...)
	if err != nil {
		return nil, err
	}
	return program, nil
}
