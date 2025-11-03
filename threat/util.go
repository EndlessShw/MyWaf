// Package threat -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/15 22:13
// @Description    : 工具类
// -------------------------------------------
package threat

import (
	"fmt"
	"github.com/bitfield/script"
	"path/filepath"
)

// ToString 将 Threat 转换成字符串
func (t Threat) ToString() string {
	if s, ok := str[t]; ok {
		return s
	}
	return ""
}

//func (t Threat) Filename() {}

// List 返回除了 Custom 和 Undefined 的 Threat 数组
func List() []Threat {
	threats := make([]Threat, len(str)-2)

	i := 0
	for threat := range str {
		switch threat {
		case Undefined, Custom:
			continue
		}
		threats[i] = threat
		i++
	}
	return threats
}

// Filename 返回文件名或者完整的文件路径
func (t Threat) Filename(isFullname bool) (string, error) {
	var path string
	var err error

	if isFullname {
		path, err = location()
		if err != nil {
			return "", err
		}
	} else {
		path = ""
	}
	if file, ok := file[t]; ok {
		return filepath.Join(path, file), nil
	}
	return "", fmt.Errorf(errFilepath, t.ToString())
}

// Count 返回指定威胁的数据库的条目数
func (t Threat) Count() (int, error) {
	// 如果指定的威胁是自定义或者是未定义，那么就没法返回条目数，只能返回 0 条
	if t <= Custom {
		return 0, nil
	}
	filePath, err := t.Filename(true)
	if err != nil {
		return 0, err
	}
	// note 用了 script 的库来编写 script 脚本
	file := script.File(filePath)
	switch t {
	// 对于 CWA，统计 json 中 filters 的 id 个数
	case CommonWebAttack:
		return file.JQ(".filters[].id").CountLines()
	case CVE:
		return file.JQ(".templates[].id").CountLines()
	default:
		// 其余类型的，统计行数就行
		return file.CountLines()
	}
}
