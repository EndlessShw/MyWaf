// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/10/15 9:43
// @Description    : 分析请求模块，包含各个攻击类型的分析
// -------------------------------------------
package MyWaf

import (
	"errors"
	"fmt"
	"github.com/EndlessShw/MyWaf/request"
	"github.com/EndlessShw/MyWaf/threat"
	"github.com/bytedance/sonic"
	"github.com/dwisiswant0/pcregexp/pkg/regexp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/net/publicsuffix"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func (myWaf *MyWaf) Analyze(rw http.ResponseWriter, req *http.Request) error {
	// note 暂时不知道返回的威胁类型有什么用
	_, err := myWaf.analyzeRequest(rw, req)
	//if err != nil {
	//	setCustomHeader(rw, xMyWafReqId, getUID())
	//}
	return err
}

// analyzeRequest 为分析请求的主体代码。
// 如果有威胁，则返回命中的类型和详细的错误。如果没有，则返回未定义类型和 nil
func (myWaf *MyWaf) analyzeRequest(rw http.ResponseWriter, req *http.Request) (threat.Threat, error) {
	// 然后遍历 Waf 内定义好的攻击类，通过 switch 导向不同的处理函数
	var err error

	// 根据具体请求，初始化 DSL
	myWaf.setDSLRequestEnv(req)
	// 先检查是否违反了用户定义的自定义规则
	err = myWaf.checkCustomRules(req)
	if err != nil {
		return threat.Custom, err
	}
	// 自定义规则通过后，接下来就要解析 Threat 类
	for _, tempThreat := range threat.InternalThreatList {
		switch tempThreat {
		case threat.CommonWebAttack:
			err = myWaf.checkCommonWebAttack(req)
		case threat.CVE:
			err = myWaf.checkCVE(req)
		case threat.BadIPAddress:
			err = myWaf.checkBadIPAddress(req)
		case threat.BadReferrer:
			err = myWaf.checkBadReferrer(req)
		case threat.BadCrawler:
			err = myWaf.checkBadCrawler(req)
		case threat.DirectoryBruteforce:
			err = myWaf.checkDirectoryBruteforce(req)
		case threat.MaliciousCommand:
			err = myWaf.checkMaliciousCommand(req)
		}
		if err != nil {
			return 0, err
		}
	}
	// 内置的和自定义的攻击类型已经检测完毕
	return threat.Undefined, nil
}

func (myWaf *MyWaf) checkCustomRules(req *http.Request) error {
	// Cache 的 key 为 headers + uri + body
	headers := myWaf.env.GetRequestValue("Headers")
	uri := myWaf.env.GetRequestValue("URI")
	body := myWaf.env.GetRequestValue("Body")
	cacheKey := headers + uri + body
	err, ok := myWaf.getCache(cacheKey)
	if ok {
		return err
	}
	// question 自定义规则应该在白名单之上吗？
	// 遍历 Rules
	for _, rule := range myWaf.opt.Customs {
		// 判断是否有 And 匹配到了
		andCount := 0
		// 遍历 Details
		for _, detail := range rule.Details {
			// 判断当前请求是否满足要求
			isMatch := false
			// 先从优先级最高的 DSL 开始检查
			if detail.DSL != "" {
				isMatch = myWaf.isDSLProgramTrue(detail.DslProgram)
			}
			// DSL 命中后判断。如果当前规则是 Or，那就命中该规则。如果是 And，那就判断下一个 Detail 是否命中。
			if isMatch {
				switch rule.Condition {
				case "or":
					myWaf.setCache(cacheKey, rule.Name)
					return errors.New(rule.Name)
				case "and":
					andCount++
				}
			}
			// 然后是判断请求方法是否命中
			switch {
			case detail.Method == request.ALL:
				isMatch = true
			case string(detail.Method) == req.Method:
				isMatch = true
			}
			// 如果请求方法都没匹配上，那就跳过当前规则细节了
			if !isMatch {
				break
			}
			isMatch = false
			// 获取当前的正则表达式
			pattern := detail.RegExp
			// 根据规则中指定的 Element，使用正则进行匹配
			switch detail.Element {
			case request.URI:
				isMatch = pattern.MatchString(uri)
			case request.Body:
				isMatch = pattern.MatchString(body)
			case request.Headers:
				isMatch = pattern.MatchString(headers)
			case request.Any:
				isMatch = pattern.MatchString(uri) || pattern.MatchString(body) || pattern.MatchString(headers)
			}
			if isMatch {
				switch rule.Condition {
				case "or":
					myWaf.setCache(cacheKey, rule.Name)
					return errors.New(rule.Name)
				case "and":
					andCount++
				}
			}
			// 如果到这未命中，而且当前规则指定的是 And，那么这条规则就不用看了，肯定就是未命中
			if rule.Condition == "and" {
				break
			}
		}
		// 到这里有两种情况，当前规则未命中或 And 内所有 detail 都全命中了
		if andCount == len(rule.Details) {
			myWaf.setCache(cacheKey, rule.Name)
			return errors.New(rule.Name)
		}
	}
	// 到这里说明自定义规则没有命中的，缓存一下
	myWaf.setCache(cacheKey, "")
	return nil
}

func (myWaf *MyWaf) checkCommonWebAttack(req *http.Request) error {
	// 先对 URL 和 Body 进行 URL Decode 和 HTML 实体类解码。同时删除特殊符号（例如换行等，以防止绕过）
	uri := removeSpecialChars(stringDeUnescape(req.URL.RequestURI()))
	body := removeSpecialChars(stringDeUnescape(myWaf.env.GetRequestValue("Body")))
	// 检查当前的请求是否在缓存中
	key := uri + body
	err, isInCache := myWaf.getCache(key)
	if isInCache {
		return err
	}
	// 再检查白名单
	for _, wlProgram := range myWaf.wlPrograms {
		if myWaf.isDSLProgramTrue(wlProgram) {
			return nil
		}
	}
	// 到此遍历所有的规则
	for _, filter := range myWaf.threatData.Cwa.Filters {
		match := filter.Pattern.MatchString(uri) || filter.Pattern.MatchString(body)
		// 如果匹配到了，存入缓存并返回
		if match {
			myWaf.setCache(key, filter.Description)
			return errors.New(filter.Description)
		}
	}
	// 如果没有匹配到，存入无消息
	myWaf.setCache(key, "")
	return nil
}

func (myWaf *MyWaf) checkCVE(req *http.Request) error {
	// 先对请求 url 和参数进行初始化
	// 获取所有的请求参数
	queryMap := req.URL.Query()
	// 存放处理后的请求参数
	reqParams := make(map[string]string)
	// 存放所有的 key
	var keyBuilder strings.Builder
	// 处理请求参数，同时汇集 key
	for key, value := range queryMap {
		// 对于同一个参数，取最初的赋值为该参数的 Value
		reqParams[key] = value[0]
		keyBuilder.WriteString(key)
		keyBuilder.WriteString(":")
		keyBuilder.WriteString(value[0])
		if len(queryMap) != 1 {
			keyBuilder.WriteString("|")
		}
	}

	// 检查 Cache
	err, isInCache := myWaf.getCache(keyBuilder.String())
	if isInCache {
		return err
	}

	// 白名单检查
	for _, wlProgram := range myWaf.wlPrograms {
		if myWaf.isDSLProgramTrue(wlProgram) {
			return nil
		}
	}

	// 遍历所有的 CVE
	for _, cveTemplate := range myWaf.threatData.Cve.Templates {
		// 遍历一个 CVE 的一条判定规则
		for _, oneReq := range cveTemplate.Requests {
			// 先判断当前访问的 URL 是否和与其中的一项匹配
			var matchedUrl *url.URL
			for _, url := range oneReq.Url {
				if req.URL.Path == url.Path {
					matchedUrl = url
					break
				}
			}
			// 如果 Url 都不匹配，那就直接跳过当前 CVE 子规则
			if matchedUrl == nil {
				continue
			}
			// 接下来就是参数匹配
			// 先存放 CVE 模板中的 URL 的参数
			cveParams := make(map[string]string)
			for paramKey, paramValue := range matchedUrl.Query() {
				cveParams[paramKey] = paramValue[0]
			}
			// note 统计一下请求参数的匹配情况，这里假设如果请求参数和请求内容匹配率（80、60 这样？）都超过一定阈值的话，那么认为当前的请求 URL 可能命中当前条目；
			// note 那还是算了，让上层指定 CVE 规则的人尽可能考虑多的情况，这里考虑请求参数要完全匹配。对于参数内容匹配，考虑到攻击者注入的命令可能不懂，这里内容匹配率以 80% 为准。
			// question 对于混淆，是否应该交给恶意命令部分来判断呢？
			// 用于统计参数的值匹配个数
			paramsValueMatchCount := 0
			isAllParamMatched := true
			// 遍历 oneReq 中的所有请求对
			for paramKey, paramValue := range cveParams {
				// 先判断所填的参数是否安全吻合
				reqParamValue := queryMap.Get(paramKey)
				// 如果有为空的，要么就是没传，要么就是传了个空值，不过一律当没有命中该规则
				if reqParamValue == "" {
					isAllParamMatched = false
					break
				}
				// 再判断对应的参数值的命中情况
				if reqParamValue == paramValue {
					paramsValueMatchCount++
				}
			}
			// 但凡有一个请求参数没有匹配，那就跳过当前规则
			if !isAllParamMatched {
				continue
			}
			// 参数值命中率大于 80% 时，考虑其符合当前的规则，需要进一步结合下面的情况判断
			if len(cveParams) > 0 && float64(paramsValueMatchCount/len(cveParams)) < 0.8 {
				continue
			}
			// 判断 Matcher 是否命中的标识
			isMatch := false
			// 统计 Matcher 中 and 的命中次数
			andCount := 0
			// 遍历 Matchers
			for _, matcher := range oneReq.Matchers {
				switch matcher.Type {
				// 判断 DSL 情况
				case "dsl":
					for _, dslProgram := range matcher.DSLPrograms {
						isDSLProgramTrue := myWaf.isDSLProgramTrue(dslProgram)
						// 如果 DSL 命中，还要考虑当前是 And 还是 Or
						if isDSLProgramTrue {
							switch matcher.Condition {
							case "and":
								andCount++
							case "or":
								isMatch = true
							}
							break
						}
					}
				case "regex":
					// 遍历当前规则下的正则表达式
					for _, regPattern := range matcher.RegPatterns {
						// 根据作用范围，调用正则表达式
						if myWaf.handleMatcherRegex(matcher.Part, regPattern) {
							switch matcher.Condition {
							case "and":
								andCount++
							case "or":
								isMatch = true
							}
							break
						}
					}
				case "word":
					if myWaf.handleMatcherWord(matcher.Part, matcher.Word) {
						switch matcher.Condition {
						case "and":
							andCount++
						case "or":
							isMatch = true
						}
					}
				}
				// 对于有 or 的情况，只要匹配到了，那就直接 return
				if isMatch {
					myWaf.setCache(keyBuilder.String(), cveTemplate.ID)
					return errors.New(cveTemplate.ID)
				}
			}
			// 判断 and 次数
			if andCount != 0 && andCount == len(oneReq.Matchers) {
				myWaf.setCache(keyBuilder.String(), cveTemplate.ID)
				return errors.New(cveTemplate.ID)
			}
			// note 编写 CVE 规则时，约定 Matcher 不能为空。因此这里无需考虑 Matcher 为空的情况
		}
	}
	// 到这说明没有 CVE 命中，返回 nil
	myWaf.setCache(keyBuilder.String(), "")
	return nil
}

// handleMatcherRegex 在 checkCVE 中负责正则表达式的处理
func (myWaf *MyWaf) handleMatcherRegex(part string, regPattern *regexp.Regexp) bool {
	switch part {
	case "URI":
		return regPattern.MatchString(myWaf.env.GetRequestValue("URI"))
	case "Headers":
		return regPattern.MatchString(myWaf.env.GetRequestValue("Headers"))
	case "Body":
		return regPattern.MatchString(myWaf.env.GetRequestValue("Body"))
	case "Method":
		return regPattern.MatchString(myWaf.env.GetRequestValue("Method"))
	case "IP":
		return regPattern.MatchString(myWaf.env.GetRequestValue("IP"))
	default:
		return regPattern.MatchString(myWaf.env.GetRequestValue("URI")) ||
			regPattern.MatchString(myWaf.env.GetRequestValue("Headers")) ||
			regPattern.MatchString(myWaf.env.GetRequestValue("Body")) ||
			regPattern.MatchString(myWaf.env.GetRequestValue("Method")) ||
			regPattern.MatchString(myWaf.env.GetRequestValue("IP"))
	}
}

// handleMatcherWord 在 checkCVE 中负责关键字部分的匹配
func (myWaf *MyWaf) handleMatcherWord(part string, word string) bool {
	switch part {
	case "URI":
		return strings.Contains(myWaf.env.GetRequestValue("URI"), word)
	case "Headers":
		return strings.Contains(myWaf.env.GetRequestValue("Headers"), word)
	case "Body":
		return strings.Contains(myWaf.env.GetRequestValue("Body"), word)
	case "Method":
		return strings.Contains(myWaf.env.GetRequestValue("Method"), word)
	case "IP":
		return strings.Contains(myWaf.env.GetRequestValue("IP"), word)
	default:
		return strings.Contains(myWaf.env.GetRequestValue("URI"), word) ||
			strings.Contains(myWaf.env.GetRequestValue("Headers"), word) ||
			strings.Contains(myWaf.env.GetRequestValue("Body"), word) ||
			strings.Contains(myWaf.env.GetRequestValue("Method"), word) ||
			strings.Contains(myWaf.env.GetRequestValue("IP"), word)
	}
}

// checkBadIPAddress 检查请求是否是恶意 IP
// 威胁数据库内每一行存放的是一个恶意 IP，每一行完全匹配
// point 是不是可以对接 IP 情报平台呢？
func (myWaf *MyWaf) checkBadIPAddress(req *http.Request) error {
	// 获取当前 IP
	clientIP := myWaf.env.GetRequestValue("IP")
	// 检查是否在缓存中
	err, ok := myWaf.getCache(clientIP)
	if ok {
		return err
	}
	// 检查白名单
	for _, wlProgram := range myWaf.wlPrograms {
		if myWaf.isDSLProgramTrue(wlProgram) {
			return nil
		}
	}
	// 如果匹配到了，那就是入缓存 + 返回错误。没匹配到就是入缓存（空消息） + 返回 nil
	// note 这个方法会抛出正则的错误，而其他使用正则的地方没有考虑正则表达式的错误
	isMatch, err := myWaf.inThreatRegexpLine(threat.BadIPAddress, clientIP)
	if err != nil {
		// 如果正则有问题，就需要记录到日志中
		myWaf.error(zapcore.ErrorLevel, err.Error())
		return nil
	}
	if isMatch {
		myWaf.setCache(clientIP, errBadIPAddress)
		return errors.New(errBadIPAddress)
	}
	myWaf.setCache(clientIP, "")
	return nil
}

// checkBadReferrer 检查请求的 Referrer 是否在黑名单中
// 威胁数据库中存放的是每一行恶意 Referrer。但是传入的 UA 可能是每一行的子字符串，因此用 contain
func (myWaf *MyWaf) checkBadReferrer(req *http.Request) error {
	// 解析 referrer
	isValid, domain, err := isValidReferrer(req.Referer())
	if err != nil {
		myWaf.error(zapcore.ErrorLevel, err.Error())
		return nil
	}
	// 如果 referrer 不是有效的，直接 return
	if !isValid {
		return nil
	}
	// 获取根域名 + 一级域名
	eTLD1, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		myWaf.error(zapcore.ErrorLevel, err.Error())
		return nil
	}
	// 先检查缓存是否存在
	err, ok := myWaf.getCache(eTLD1)
	if ok {
		return err
	}
	// 然后检查白名单
	for _, wlProgram := range myWaf.wlPrograms {
		if myWaf.isDSLProgramTrue(wlProgram) {
			return nil
		}
	}
	// 然后调用正则匹配
	// note 考虑 eTLD1 可能也是恶意域名的一部分，因此不用 myWaf.inThreatRegexpLine
	if myWaf.inThreatIndex(threat.BadReferrer, domain) {
		myWaf.setCache(eTLD1, errBadReferrer)
		return errors.New(errBadReferrer)
	}
	myWaf.setCache(eTLD1, "")
	return nil
}

// checkBadCrawler 检查 UA 头是否命中黑名单
// 威胁库中每一行存放恶意爬虫 UA 头的正则表达式。
func (myWaf *MyWaf) checkBadCrawler(req *http.Request) error {
	// 拿到 UA 头并判断是否为空
	ua := req.UserAgent()
	if ua == "" {
		return nil
	}
	// 检查缓存
	if err, ok := myWaf.getCache(ua); ok {
		return err
	}
	// 检查白名单
	for _, wlProgram := range myWaf.wlPrograms {
		if myWaf.isDSLProgramTrue(wlProgram) {
			return nil
		}
	}
	// 循环正则表达
	for _, pattern := range myWaf.threatData.BadCrawler {
		if pattern.MatchString(ua) {
			myWaf.setCache(ua, errBadCrawler)
			return errors.New(errBadCrawler)
		}
	}
	myWaf.setCache(ua, "")
	return nil
}

// checkDirectoryBruteforce 检查访问的文件等是否是敏感文件
// 威胁数据库每一行都是一个敏感文件名或相对路径
func (myWaf *MyWaf) checkDirectoryBruteforce(req *http.Request) error {
	// 先检查路径是否就是 `/`，如果是就不用检查了
	path := req.URL.Path
	if path == "/" {
		return nil
	}
	// 检查缓存
	if err, ok := myWaf.getCache(path); ok {
		return err
	}
	// 检查白名单
	for _, wlProgram := range myWaf.wlPrograms {
		if myWaf.isDSLProgramTrue(wlProgram) {
			return nil
		}
	}
	// 匹配
	if myWaf.inThreatIndex(threat.DirectoryBruteforce, path) {
		myWaf.setCache(path, errDirectoryBruteforce)
		return errors.New(errDirectoryBruteforce)
	}
	myWaf.setCache(path, "")
	return nil
}

// checkMaliciousCommand 检查请求包中是否含有恶意命令
// 匹配的规则是使用正则表达式
func (myWaf *MyWaf) checkMaliciousCommand(req *http.Request) error {
	// todo 应该添加缓存，但是 key 应该如何定义？
	// 检查白名单
	for _, wlProgram := range myWaf.wlPrograms {
		if myWaf.isDSLProgramTrue(wlProgram) {
			return nil
		}
	}
	// 对其请求 URL 的参数、HTTP 请求头、请求体检查
	query := req.URL.Query()
	headers := req.Header
	// 检查 URL 参数
	for _, queryValues := range query {
		for _, pattern := range myWaf.threatData.MaliciousCommand {
			for _, queryValue := range queryValues {
				if pattern.MatchString(queryValue) {
					return errors.New(errMaliciousCommand)
				}
			}
		}
	}
	// 检查所有的 headers
	for _, headerValues := range headers {
		for _, pattern := range myWaf.threatData.MaliciousCommand {
			for _, headerValue := range headerValues {
				if pattern.MatchString(headerValue) {
					return errors.New(errMaliciousCommand)
				}
			}
		}
	}
	// 检查 body
	body := myWaf.env.GetRequestValue("Body")
	if body == "" {
		return nil
	}
	for _, pattern := range myWaf.threatData.MaliciousCommand {
		if pattern.MatchString(body) {
			return errors.New(errMaliciousCommand)
		}
	}
	return nil
}

// postAnalyze 为拦截之后的行为
func (myWaf *MyWaf) postAnalyze(rw http.ResponseWriter, req *http.Request, err error, threatType threat.Threat) {
	// 如果没有传入拦截时产生的 error，直接 return
	if err == nil {
		return
	}
	// 获取 UID
	uid := getUID()
	// 从 error 中获取具体信息
	msg := err.Error()
	// 将信息、命中的威胁类型、UID 写入响应头
	setCustomHeader(rw, XMyWafMsg, msg)
	setCustomHeader(rw, xMyWafReqId, uid)
	setCustomHeader(rw, xMyWafThreatType, threatType.ToString())
	// 记录日志
	myWaf.sendLogs(req, threatType, uid, msg)
	// 执行 reject handler 的 Serve
	myWaf.rejectHandler.ServeHTTP(rw, req)
}

// sendLogs 向日志和 falcosidekick（如果配置了）发送事件信息
func (myWaf *MyWaf) sendLogs(req *http.Request, threatType threat.Threat, uid, msg string) {
	// 部分待记录的参数初始化
	threatTypeStr := threatType.ToString()
	caller := myWaf.caller
	listenAddr := myWaf.getListenAddr(req)
	query := req.URL.Query()
	ipAddr := myWaf.env.GetRequestValue("IP")
	body := myWaf.env.GetRequestValue("Body")
	// 记录 id、威胁类型、caller、服务地址；以及请求的 Method、路径、GET 参数、请求 IP、headers、请求体
	myWaf.logger.With(
		zap.String("uid", uid),
		zap.String("threatType", threatTypeStr),
		zap.String("caller", caller),
		zap.String("listenAddr", listenAddr),
		zap.Namespace("request"),
		zap.String("method", req.Method),
		zap.String("path", req.URL.Path),
		zap.Any("query", query),
		zap.String("IP", ipAddr),
		zap.Any("headers", req.Header),
		zap.String("body", body),
	).Warn(msg)

	if myWaf.opt.FalcosidekickURL == "" {
		return
	}
	// 实例化
	event := new(falcoEvent)
	// 记录当前时间
	now := time.Now()
	// req.Header 需要序列化成 JSON
	headerJson, err := sonic.Marshal(req.Header)
	if err != nil {
		myWaf.error(zapcore.PanicLevel, err.Error())
	}
	// 初始化 falcoEvent
	event.Output = fmt.Sprintf(
		"%s: %s at %s by %s (caller=%s threat=%s id=%s)",
		now.Format("15:04:05.000000000"), msg, req.URL.Path, ipAddr, caller, threatTypeStr, uid,
	)
	event.Priority = "Warning"
	event.Rule = msg
	event.Time = now.Format("2006-01-02T15:04:05.999999999Z")
	event.OutputFields.Caller = caller
	event.OutputFields.ID = uid
	event.OutputFields.Threat = threatTypeStr
	event.OutputFields.ListenAddr = listenAddr
	event.OutputFields.RequestBody = body
	event.OutputFields.RequestHeaders = string(headerJson)
	event.OutputFields.RequestIPAddr = ipAddr
	event.OutputFields.RequestMethod = req.Method
	event.OutputFields.RequestPath = req.URL.Path

	// 上个锁来更新一下事件 slice
	myWaf.falcoSidekick.sl.Lock()
	myWaf.falcoSidekick.events = append(myWaf.falcoSidekick.events, event)
	myWaf.falcoSidekick.sl.Unlock()
}
