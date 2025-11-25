// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/22 23:07
// @Description    : 上层常用工具类
// -------------------------------------------
package MyWaf

import (
	"MyWaf/request"
	"MyWaf/threat"
	"bytes"
	"errors"
	"github.com/dwisiswant0/clientip"
	"github.com/expr-lang/expr/vm"
	"github.com/patrickmn/go-cache"
	"github.com/twharmon/gouid"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

func (myWaf *MyWaf) error(level zapcore.Level, msg string) {
	// point zap.WithCaller 是为了详细的添加调用者的相关信息，从而帮助定位问题
	// point zap.AddCallerSkip 是为了跳过当前的调用链，因为此时 logger 的调用者是一个封装的函数，
	// point 而最终想要获取的业务上的调用者则需要知道封装函数的调用者。因此需要跳过一层。
	// point WithOptions 是拷贝 logger
	logger := myWaf.logger.WithOptions(zap.WithCaller(true), zap.AddCallerSkip(1))
	switch level {
	case zapcore.ErrorLevel:
		logger.Error(msg)
	case zapcore.PanicLevel:
		logger.Panic(msg)
	case zapcore.DPanicLevel:
		logger.DPanic(msg)
	}
}

// isValidMethod 检查传入的 request.Method 是否有效
func isValidMethod(method request.Method) bool {
	switch method {
	case request.GET, request.HEAD, request.POST, request.DELETE, request.PUT,
		request.OPTIONS, request.CONNECT, request.TRACE, request.PATCH, request.ALL, "":
		return true
	}
	return false
}

// normalizeRawStringReader 去掉 HTTP raw（原始）字符串中的多余双引号，
// 将双反斜的 CR 和 LR 换成单反斜，同时末尾添加两个 CRLF。
// 结果返回一个 strings.Reader 的指针
func normalizeRawStringReader(raw string) *strings.Reader {
	var builder strings.Builder

	raw = strings.Trim(raw, `"`)
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	raw = strings.ReplaceAll(raw, "\\r", "\r")
	builder.WriteString(raw)
	builder.WriteString("\r\n\r\n")
	return strings.NewReader(builder.String())
}

// setDSLRequestEnv 会根据当前传入的 Request 来设置 DSL 的环境
func (myWaf *MyWaf) setDSLRequestEnv(req *http.Request) {
	// headers 转换成 raw string
	headers := headersToRawString(req.Header)
	// uri 要先 urldecode 然后 htmlEscape
	uri := stringDeUnescape(req.URL.RequestURI())
	// 最终存放请求体字符串的变量
	var body string

	if req.Body != nil {
		// 暂存请求体内容的缓冲区
		buf := &bytes.Buffer{}
		// todo 需要在前面的地方限制请求体的大小
		_, err := io.Copy(buf, req.Body)
		// 如果拷贝成功，就要给 body 复原（也就是还原其 io.Reader）
		if err == nil {
			req.Body = io.NopCloser(buf)
			body = buf.String()
		}
		body = stringDeUnescape(body)
	}

	// 设置 DSL 环境（看样子是一次请求一个 DSL 环境）
	myWaf.env.RequestInfo = map[string]interface{}{
		"URI":     uri,
		"Headers": headers,
		"Body":    body,
		"Method":  req.Method,
		"IP":      clientip.FromRequest(req).String(),
	}
}

// headersToRawString 将 HTTP Headers 所有数据转换成字符串。
// 其中一个 header 的值是 []string，因此需要嵌套循环
func headersToRawString(headers http.Header) string {
	var strbuilder strings.Builder

	// 先遍历所有的键值对
	for key, values := range headers {
		// 然后再遍历 values 中的所有 value
		for _, value := range values {
			strbuilder.WriteString(url.QueryEscape(key))
			strbuilder.WriteString(":")
			strbuilder.WriteString(url.QueryEscape(value))
		}
		strbuilder.WriteString("\n")
	}

	return strbuilder.String()
}

// stringDeUnescape 将传入的字符串进行 URL 解码和实体字符转义（有先后顺序）
func stringDeUnescape(str string) string {
	str = url.QueryEscape(str)
	return html.UnescapeString(str)
}

// getCache 返回传入的 key 是否已经缓存
// @return 第一个参数返回缓存中的 value（也就是具体的错误信息）
// @return 第二个参数返回缓存是否命中
func (myWaf *MyWaf) getCache(key string) (error, bool) {
	if myWaf.opt.NoReqCache {
		return nil, false
	}

	// 注意 cache 中存放的是请求的违规错误
	msg, ok := myWaf.cache.Get(key)
	if ok {
		if msg == nil {
			return nil, ok
		}
		return msg.(error), ok
	}

	return nil, false
}

// setCache 就是将拦截的错误存入缓存中。如果设置成不使用缓存的话，那么就直接 return
// @param msg 就是错误信息，如果 msg 为 nil 或者 empty 则存入 nil。
func (myWaf *MyWaf) setCache(key string, msg string) {
	if myWaf.opt.NoReqCache {
		return
	}

	var err error

	if msg != "" {
		err = errors.New(msg)
	} else {
		err = nil
	}

	myWaf.cache.Set(key, err, cache.DefaultExpiration)
}

// isDSLProgramTrue 将传入的 DSL 表达式（这里特指 Boolean 判断表达式）编译并执行，返回表达式的结果
func (myWaf *MyWaf) isDSLProgramTrue(program *vm.Program) bool {
	dslEval, err := myWaf.env.Run(program)
	if err != nil {
		return false
	}
	return dslEval.(bool)
}

func removeSpecialChars(str string) string {
	// 替换所有的换行
	str = strings.ReplaceAll(str, "\n", "")
	// 替换所有的回车
	str = strings.ReplaceAll(str, "\r", "")
	// 替换所有的水平制表符
	str = strings.ReplaceAll(str, "\t", "")
	// 替换所有的退格 backspace
	str = strings.ReplaceAll(str, "\b", "")
	// 替换所有的换页符
	str = strings.ReplaceAll(str, "\f", "")
	// todo ascii 表前几个可能都需要替换掉
	return str
}

// inThreatRegexpLine 检查传入的字符串是否是某个威胁库中的一行（威胁库的数据是一行一行的）
func (myWaf *MyWaf) inThreatRegexpLine(threatType threat.Threat, p string) (bool, error) {
	var pattern strings.Builder
	// `(^m)` 表示多行匹配，也就是一行一次匹配
	pattern.WriteString("(^m)^")
	pattern.WriteString(regexp.QuoteMeta(p))
	pattern.WriteString("$")
	return regexp.MatchString(pattern.String(), myWaf.threatData.Data[threatType])
}

// inThreatIndex 检查传入的字符串是否是威胁库的子字符串
func (myWaf *MyWaf) inThreatIndex(threatType threat.Threat, substr string) bool {
	if i := strings.Index(myWaf.threatData.Data[threatType], substr); i >= 0 {
		return true
	}
	return false
}

// isValidReferrer 从传入的字符串中解析出域名，如果解析不出来返回 false。传入的字符串有误而返回 error
func isValidReferrer(referrer string) (bool, string, error) {
	parsedUrl, err := url.Parse(referrer)
	if err != nil {
		return false, "", err
	}
	host := parsedUrl.Hostname()
	if host == "" {
		return false, "", nil
	}
	// point publicsuffix 为官方提供的域名解析包
	// eTLD 为 effective Top-Level Domain，也就是根域名，例如 .com、.cn 等
	// icann 是 bool，用于判断该域名是否受 icann 管控，官方给出了使用案例。
	eTLD, icann := publicsuffix.PublicSuffix(host)
	// 后半部分表示该域名不受 icann 管控，不过这两种情况都表明他是域名
	if icann || strings.IndexByte(eTLD, '.') >= 0 {
		return true, host, nil
	}
	return false, host, nil
}

// 该方法不用，需要获取 body 时通过 MyWaf.env.GetRequestValue("Body")
// getBodyStr 用于获取经过 UrlDecode 和 HTML 实体解码的请求体
//func (myWaf *MyWaf) getBodyStr(req *http.Request) string {
//	body := ""
//	if req.Body != nil {
//		// 暂存请求体内容的缓冲区
//		buf := &bytes.Buffer{}
//		// todo 需要在前面的地方限制请求体的大小，当超过这个大小时，将其截断后发往后续的业务 handler 中
//		_, err := io.Copy(buf, req.Body)
//		// 如果拷贝成功，就要给 body 复原（也就是还原其 io.Reader）
//		if err == nil {
//			req.Body = io.NopCloser(buf)
//			body = buf.String()
//		}
//		body = stringDeUnescape(body)
//	}
//	return body
//}

func setCustomHeader(rw http.ResponseWriter, key, value string) {
	rw.Header().Set(key, value)
}

// getUID 使用 gouid 库随机生成 10 位数 ID
// todo ID 目前没有更深一步的作用，缓存中也没有用到。后续再说.
func getUID() string {
	return gouid.Bytes(10).String()
}

// getListenAddr 获取 HTTP Server 部署的地址。同时用 Cache 存储地址以便获取
func (myWaf *MyWaf) getListenAddr(req *http.Request) string {
	cacheKey := "listen_addr"
	if listenAddrCache, ok := myWaf.cache.Get(cacheKey); ok {
		return listenAddrCache.(string)
	}
	// note 无侵入式获取当前 HTTP 部署的地址：https://stackoverflow.com/questions/52060812/get-the-port-of-the-local-http-server-without-hijacking-the-connection/52061671#52061671
	if serverAddr, ok := (req.Context().Value(http.LocalAddrContextKey)).(net.Addr); ok {
		listenAddr := serverAddr.String()
		myWaf.cache.Set(cacheKey, listenAddr, cache.DefaultExpiration)
		return listenAddr
	}
	return ""
}
