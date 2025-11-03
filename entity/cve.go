// Package entity -----------------------------
// @author         : EndlessShw
// @time           : 2025/10/5 13:51
// @Description    : CVE 的对应实体类
// -------------------------------------------
package entity

import (
	"fmt"
	"github.com/dwisiswant0/pcregexp/pkg/regexp"
	"github.com/expr-lang/expr/vm"
	"net/url"
)

type CVE struct {
	Templates []*struct {
		ID   string `json:"id"`
		Info *struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		}
		Requests []*struct {
			// Raw 和 Path 二选一，如果都有以 Path 为准，最终都会转化成 Url
			Raw  []string   `json:"raw"`
			Path []string   `json:"path"`
			Url  []*url.URL `json:"-"`
			// 如果有 MatchersCondition，那么内部的 Condition 就会被忽略
			MatchersCondition string `json:"matchers-condition"`
			Matchers          []*struct {
				// Type 指定匹配规则，dsl、regex、word、status 三选一
				// 其中 Regex 和 Word 需要指定作用范围（请求体对应 dsl.Env 的 RequestInfo）
				Type  string   `json:"type"`
				DSL   []string `json:"dsl"`
				Regex []string `json:"regex"`
				Word  string   `json:"word"`
				// regex 和 word 的作用范围，和 DSL 的 dsl.Env 中的 RequestInfo 对应。
				Part string `json:"part"`
				// status 指定匹配的响应码
				Status []uint8 `json:"status"`
				// 指定这个规则是 And 还是 Or
				Condition   string           `json:"condition"`
				RegPatterns []*regexp.Regexp `json:"-"`
				DSLPrograms []*vm.Program    `json:"-"`
			}
		} `json:"requests"`
	} `json:"templates"`
}

// Print 为 Debug 时用的打印函数
func (cve *CVE) Print() {
	for _, template := range cve.Templates {
		fmt.Printf("ID is %s", template.ID)
		fmt.Print("\nInfo:")
		fmt.Printf("\n\tName: %s", template.Info.Name)
		fmt.Printf("\n\tSeverity: %s", template.Info.Severity)
		fmt.Printf("\nRequests: ")
		for i, request := range template.Requests {
			fmt.Printf("\n\tThe %v request is: ", i)
			fmt.Printf("\n\t\tRaw is:")
			for _, raw := range request.Raw {
				fmt.Printf("\n\t\t\t%s ", raw)
			}
			fmt.Printf("\n\t\tPath is:")
			for _, path := range request.Path {
				fmt.Printf("\n\t\t\t%s ", path)
			}
			fmt.Printf("\n\tMatchersCondition is: %s", request.MatchersCondition)
			fmt.Printf("\n\tMatchers:")
			for _, matcher := range request.Matchers {
				fmt.Printf("\n\t\t%s ", matcher.Type)
				if matcher.Type == "dsl" {
					fmt.Printf("\n\t\tDSL is:")
					fmt.Printf("\n\t\t\t%v", matcher.DSL)
				}
				if matcher.Type == "regex" {
					fmt.Printf("\n\t\tRegex is:")
					fmt.Printf("\n\t\t\t%v", matcher.Regex)
				}
				if matcher.Type == "word" {
					fmt.Printf("\n\t\tWords is:")
					fmt.Printf("\n\t\t\t%v", matcher.Word)
				}
				fmt.Printf("\n\t\tPart is: %s ", matcher.Part)
				fmt.Printf("\n\t\tCondition is: %s", matcher.Condition)
			}
			fmt.Printf("\n\t\t%v\t%v", request.MatchersCondition, request.Matchers)
		}
		fmt.Printf("\n")
	}
}
