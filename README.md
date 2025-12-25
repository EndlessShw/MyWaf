# MyWaf
从 Golang 开始学安全开发！

# 对外开放的 API
## 1. 实例化 `MyWaf`，对流入流量过滤
1. 详细使用方法可见 example
## 2. 对外暴露分析模块，可以直接调用
1. 先实例化 `MyWaf`，然后调用其分析模块：
```go
package test

import (
	"github.com/EndlessShw/MyWaf"
	"log"
	"net/http"
	"testing"
)

func Test_Analyze(t *testing.T) {
	request, err := http.NewRequest("GET", "http://localhost:8080/analyze?param1=value1&param2=cat%20/etc/passwd", nil)
	if err != nil {
		log.Fatalf("fail to create request, err is %v", err)
	}
	myWaf := MyWaf.New()
	err = myWaf.Analyze(nil, request)
	if err != nil {
		log.Printf("detect threat! err is %v", err)
	}
}

```

## 功能需求
### 1. 通用主题功能
1. MyWaf 可以额外写成组件的形式，将 analyze 模块对外提供，这样 IDS 可以直接调用分析模块。
2. 更换 Cache 组件，使用自己之前编写的 Cache
3. TODO：IDS 上引入数据库，可以对事件进行相关操作，包括但不限于封锁 IP、加白等，往态势感知平台上靠拢

### 2. 具体业务更改
1. CommonWebAttack 增加 URL Decode 和 HTML 实体编码
2. CVE 模块中对 Path 的处理不够，得考虑路径穿越和大小写绕过等问题
3. 原先 CVE 模块中判断是否命中是检查所有的请求参数是否完全对应。如果依旧使用全匹配，那么在写规则模板时就要考虑最小原则。
4. 添加恶意命令检测，包括但不限于反弹 Shell，查看系统敏感文件，通用命令等。

## TODO List
- [x] Threat 数据库同步功能
- [ ] 测试同步功能
- [ ] Analyze 模块需要返回 data map，用来对接 Prometheus 等。
- [ ] Analyze 模块下，CVE 和 Custom Rule 需要返回某些特定内容。
