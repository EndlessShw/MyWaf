// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/24 10:02
// @Description    : 应用测试类
// -------------------------------------------
package MyWaf

import (
	"MyWaf/entity"
	"github.com/bytedance/sonic"
	"log"
	"os"
	"testing"
)

// Test_yamlToRule 测试用户自定义反序列化是否有问题
func Test_yamlToRule(t *testing.T) {
	filePath := "./my-waf.yaml"
	file, err := os.Open(filePath)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	rules, errors := yamlToRules(file)
	for _, yamlErr := range errors {
		log.Printf("%v\n", yamlErr)
	}
	for _, rule := range rules {
		log.Printf("rule is %s", rule.Name)
		for _, detail := range rule.Details {
			log.Printf("rule.Detail.RegPattern is %s", detail.RegPattern)
			log.Printf("rule.Detail.DSL is %s", detail.DSL)
		}
		log.Println()
	}
}

// Test_unmarshalCVE 测试 CVE.json 反序列化是否有问题
func Test_unmarshalCVE(t *testing.T) {
	cve := &entity.CVE{}
	cveFile, err := os.ReadFile("cve.json")
	if err != nil {
		log.Fatalf("fail to open cve.json, err is %v", err)
	}
	err = sonic.Unmarshal(cveFile, cve)
	if err != nil {
		log.Fatalf("fail to unmarshal cve, err is %v", err)
	}
	cve.Print()
}

func TestNew(t *testing.T) {
	myWaf := New()
	println(myWaf)
}
