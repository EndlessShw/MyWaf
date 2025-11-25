// Package dsl -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 22:37
// @Description    : 测试
// -------------------------------------------
package dsl

import (
	"MyWaf/threat"
	"log"
	"testing"
)

// TestVarsIsPointer 测试 Env.vars 的 value 改成指针是否可行
func TestVarsIsPointer(t *testing.T) {
	env := NewEnv()
	env.Threat = threat.CommonWebAttack
	env.RequestInfo = map[string]any{
		"URI":  "https://www.test.com",
		"Body": "This is a test body",
	}
	compile, err := env.Compile("request.URI == 'https://www.test.com'")
	if err != nil {
		log.Fatalf("compile error: %v", err)
	}
	run, err := env.Run(compile)
	if err != nil {
		log.Fatalf("failed to run: %v", err)
	}
	log.Printf("result is %v", run)
	log.Printf("the requestInfo in env.vars is %v", env.vars["request"])
}
