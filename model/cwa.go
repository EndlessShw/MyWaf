// Package model -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 23:57
// @Description    : 一条 CommonWebAttack 结构体
// -------------------------------------------
package model

// point Teler 原作者写了一个正则的库
import "github.com/dwisiswant0/pcregexp/pkg/regexp"

type CWA struct {
	Filters []struct {
		Description string   `json:"description"`
		ID          int64    `json:"id"`
		Impact      int64    `json:"impact"`
		Rule        string   `json:"rule"`
		Tags        []string `json:"tags"`
		Pattern     *regexp.Regexp
	} `json:"filters"`
}
