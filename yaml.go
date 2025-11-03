// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/23 10:57
// @Description    : 将 yaml 文件中的 Custom 规则反序列化成结构体
// -------------------------------------------
package MyWaf

import (
	"MyWaf/option"
	"MyWaf/request"
	"fmt"
	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
	"io"
	"os"
)

type yamlDetail struct {
	Method     string `yaml:"method,omitempty"`
	Element    string `yaml:"element,omitempty"`
	RegPattern string `yaml:"regPattern,omitempty"`
	DSL        string `yaml:"dsl,omitempty"`
}

type yamlRule struct {
	Name      string       `yaml:"name" validate:"required"`
	Condition string       `yaml:"condition,omitempty"`
	Details   []yamlDetail `yaml:"details" validate:"required,dive"`
}

// yamlToRules 将一个 Yaml 文件转成 Rules（Slice）
// Point 源项目中不懂为什么只输出一个 Rule，总不可能一个文件只对应一个 Rule 吧。
// Point 源项目中也没有给 YAML 的规则文件格式，example 给的 yaml 解析有问题。例如 Element 的指定。
func yamlToRules(file *os.File) ([]option.Rule, []error) {
	defer file.Close()
	// 先创建 validator 实例
	validate := validator.New()
	// 初始化 yamlRule 和 option.Rule 的 Slice
	var rules []option.Rule
	var yamlRules []*yamlRule
	// 读取 YAML 文件内容
	yamlData, err := io.ReadAll(file)
	if err != nil {
		return nil, []error{fmt.Errorf(errReadFile, file.Name(), err)}
	}
	// 反序列化 YAML
	err = yaml.Unmarshal(yamlData, &yamlRules)
	if err != nil {
		return nil, []error{fmt.Errorf(errUnmarshalYAML, file.Name(), err)}
	}

	var errs []error

	// 针对每一个反序列化的 Rule，进行转换适配
	for _, yamlRule := range yamlRules {
		// 实例化 Rule
		rule := option.Rule{}
		// 完成 Rule.Name 和 Rule.Condition 的赋值
		rule.Name = yamlRule.Name
		if yamlRule.Condition == "" {
			yamlRule.Condition = option.DefaultCondition
		}
		rule.Condition = yamlRule.Condition
		// 初始化 Rule.Details
		rule.Details = make([]option.Detail, len(yamlRule.Details))
		// 遍历 yamlRule 中的 yamlDetail，然后进行映射
		for i, yamlDetail := range yamlRule.Details {
			// 有 DSL 的优先 DSL
			if yamlDetail.DSL != "" {
				rule.Details[i].DSL = yamlDetail.DSL
				continue
			}
			// 如果 DSL 和 RegPattern 都为空，那么这条子规则失效
			if yamlDetail.DSL == "" && yamlDetail.RegPattern == "" {
				errs = append(errs, fmt.Errorf(errInvalidYAMLRule, yamlRule.Name, "DSL and pattern cannot be empty"))
				continue
			}
			// 如果 Method、Element 为空，那么取默认值（ALL 和 Any，也就是全部）
			if yamlDetail.Method == "" {
				yamlDetail.Method = option.DefaultMethod
			}
			if yamlDetail.Element == "" {
				yamlDetail.Element = option.DefaultElement
			}
			// 将 Method 和 Element 字符串转换成对应的类
			rule.Details[i].Method = request.ToMethod(yamlDetail.Method)
			if rule.Details[i].Method == request.UNDEFINED {
				errs = append(errs, fmt.Errorf(errInvalidYAMLRule, yamlRule.Name, "Method may be wrong"))
				continue
			}
			rule.Details[i].Element = request.ToElement(yamlDetail.Element)
			if rule.Details[i].Element == request.Undefined {
				errs = append(errs, fmt.Errorf(errInvalidYAMLRule, yamlRule.Name, "Element may be wrong"))
				continue
			}
			rule.Details[i].RegPattern = yamlDetail.RegPattern
		}
		// 经过一系列初始化和修改后，对 yamlRule 进行 validate 验证
		err = validate.Struct(yamlRule)
		if err != nil {
			errs = append(errs, fmt.Errorf(errInvalidYAMLRule, yamlRule.Name, err))
			continue
		}
		rules = append(rules, rule)
	}
	// 把期间遇到的解析问题统计后 return 出去
	return rules, errs
}
