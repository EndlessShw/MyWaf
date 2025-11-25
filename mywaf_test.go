// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/24 10:02
// @Description    : 应用测试类
// -------------------------------------------
package MyWaf

import (
	"MyWaf/internal/model"
	"github.com/bytedance/sonic"
	"log"
	"net/http"
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
	cve := &model.CVE{}
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

// Test_Analyze 测试 MyWaf 是否可以模块化
// 结果是可以模块化
func Test_Analyze(t *testing.T) {
	request, err := http.NewRequest("GET", "http://localhost:8080/analyze?param1=value1&param2=cat%20/etc/passwd", nil)
	if err != nil {
		log.Fatalf("fail to create request, err is %v", err)
	}
	myWaf := New()
	err = myWaf.Analyze(nil, request)
	if err != nil {
		log.Printf("detect threat! err is %v", err)
	}
}
