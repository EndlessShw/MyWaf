// Package option -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 22:43
// @Description    : 一条规则，里面有三个部分
// -------------------------------------------
package option

type Rule struct {
	// Name 表示规则的名称
	Name string `json:"name" yaml:"name"`

	// Condition 表示规则内 Detail 的适用条件，值为与或（`and` 和 `or`）
	Condition string `json:"condition" yaml:"condition"`

	// RuleDetail 是一条规则的细节，为 Details 类的 list。
	Details []Detail `json:"details" yaml:"details"`
}
