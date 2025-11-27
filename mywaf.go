// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 14:51
// @Description    : 主类，主要负责实例创建和初始化、流入流量的预处理等
// -------------------------------------------
package MyWaf

import (
	"archive/tar"
	"bufio"
	"fmt"
	"github.com/EndlessShw/MyWaf/internal/dsl"
	"github.com/EndlessShw/MyWaf/internal/model"
	"github.com/EndlessShw/MyWaf/option"
	"github.com/EndlessShw/MyWaf/request"
	"github.com/EndlessShw/MyWaf/threat"
	"github.com/bytedance/sonic"
	"github.com/dwisiswant0/pcregexp/pkg/regexp"
	"github.com/expr-lang/expr/vm"
	"github.com/klauspost/compress/zstd"
	"github.com/patrickmn/go-cache"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
	"tlog.app/go/loc"
)

type MyWaf struct {
	// opt 为应用的配置类
	opt option.Options

	// logOut 为日志的文件句柄
	logOut *os.File

	// logger 为日志实例
	logger *zap.Logger

	// threatData 为威胁数据库的包装类
	threatData *model.ThreatData

	// rejectHandler 为拒绝或阻断的 Handler
	rejectHandler http.Handler

	// wlPrograms 为白名单编译后的 DSL 语句
	wlPrograms []*vm.Program

	// todo 先用别人的 Cache 依赖，后面换上自己的
	cache *cache.Cache

	// caller 为调用当前应用程序的包名
	caller string

	// env 为 DSL 的环境
	env *dsl.Env

	// falcoSidekick 为类 falco 事件的结构体，存放同步到 falcosidekick 的事件 slice 和对应的锁
	falcoSidekick falcoSidekick
}

func New(opts ...option.Options) *MyWaf {
	// todo 这个项目没有从 yaml 来解析 option，这里还得添加 flag（或者应该交给上层解析？）
	var opt option.Options

	// 如果没有传入 Option，那就创建一个默认的。否则只取第一个 Option
	if len(opts) == 0 {
		opt = option.Options{}
	} else {
		opt = opts[0]
	}

	// 创建 Waf 实例并初始化其 rejectHandler 和 threatData
	myWaf := &MyWaf{
		rejectHandler: http.HandlerFunc(defaultRejectHandler),
		threatData:    &model.ThreatData{},
	}

	// 使用 loc.Caller 获取调用者的包名
	if pc := loc.Caller(1); pc != 0 {
		// 获取调用者的文件路径名
		_, file, _ := pc.NameFileLine()
		// 取最后一部分
		myWaf.caller = path.Base(path.Dir(file))
	}

	// 创建 zap 的 io.Writer，也就是日志的 writer
	// note 这里实际上使用的是 zapcore 库，也就是 zap 的核心库。直接调用 zap 库的底层接口以实现定制化
	// todo zap 官方给的教程很小，这里还涉及到 zapcore，因此需要读源码
	var writeSyncers []zapcore.WriteSyncer

	// 将 stderr 添加到 zap 的 writer
	if !opt.NoStderr {
		writeSyncers = append(writeSyncers, os.Stderr)
	}

	// 将配置文件中用户定义的 LogWriter 添加到 zap 的 writer
	if opt.LogWrite != nil {
		writeSyncers = append(writeSyncers, zapcore.AddSync(opt.LogWrite))
	}
	// 将用户定义的日志文件 LogFile 作为文件句柄添加到 zap 的 writer 中
	var err error
	if opt.LogFile != "" {
		myWaf.logOut, err = os.OpenFile(opt.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			// 这时日志还没初始化完成，因此直接打印到控制台上
			panic(fmt.Sprintf(errLogFile, opt.LogFile))
		}
	}
	// 定义默认的日志等级为 warning（即只记录 warning 以上等级的），如果为 Verbose 就是 Debug
	logLevel := zap.WarnLevel
	if opt.Verbose {
		logLevel = zapcore.DebugLevel
	}
	// 创建 zap 实例并完成相关设置
	myWaf.logger = zap.New(zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.NewMultiWriteSyncer(writeSyncers...),
		logLevel,
	))
	// 记录第一条日志，内容为应用启动时的相关设置
	myWaf.logger.Info("myWaf application option", zap.Any("option", opt))
	// 推迟执行日志同步函数，将输入流的 buffer 进行刷新
	defer func() {
		_ = myWaf.logger.Sync()
	}()
	// DSL Env 初始化
	myWaf.env = dsl.NewEnv()
	// 编译白名单，失败的记录到日志中
	for _, whitelist := range opt.Whitelists {
		myWaf.logger.Debug("compiling whitelist", zap.String("whitelist", whitelist))
		program, err := myWaf.env.Compile(whitelist)
		if err != nil {
			// point 将日志的 error 和 panic 包装成一个函数来调用
			myWaf.error(zap.PanicLevel, fmt.Sprintf(errCompileDSLExpr, whitelist, err.Error()))
			continue
		}
		myWaf.wlPrograms = append(myWaf.wlPrograms, program)
	}
	// 解析 opt 中的 custom 部分。分为两部分，一部分是从文件解析，另外一部分是从代码中解析
	// 首先是从文件中解析，统一转换成从文本解析
	if opt.CustomsFromFile != "" {
		// point filepath.Glob 根据路径获取所有文件的路径（路径一般有通配符）
		customRuleFilePaths, err := filepath.Glob(opt.CustomsFromFile)
		if err != nil {
			myWaf.error(zap.PanicLevel, fmt.Sprintf(errFindFile, opt.CustomsFromFile, err.Error()))
		}
		// 遍历所有的文件
		for _, customRuleFilePath := range customRuleFilePaths {
			myWaf.logger.Debug("load CustomsFromFile", zap.String("file", customRuleFilePath), zap.String("filePath", opt.CustomsFromFile))
			customRuleFile, err := os.Open(customRuleFilePath)
			if err != nil {
				myWaf.error(zap.PanicLevel, fmt.Sprintf(errOpenFile, customRuleFilePath, err.Error()))
			}
			customRules, errors := yamlToRules(customRuleFile)
			for _, err := range errors {
				// 内层错误已经包含了具体是哪一条规则有问题，这里就不再添加 rule 了
				myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errConvYAML, err))
			}
			opt.Customs = append(opt.Customs, customRules...)
		}
	}
	// 从代码中解析
	// todo 文件解析的时候就对字段经过了一段预处理，这里还要对其进行预处理。有一些重复操作，可能可以优化
	for _, customRule := range opt.Customs {
		if customRule.Name == "" {
			// 虽然名字为空，但是规则依旧可以生效，并提示用户进行检查。
			myWaf.error(zapcore.PanicLevel, errInvalidRuleName)
		}
		// 将添加的规则信息写入日志，开发过程中以便查看
		myWaf.logger.Debug("load custom rule", zap.Any("rule", customRule))
		// 处理 condition
		customRule.Condition = strings.ToLower(customRule.Condition)
		if customRule.Condition == "" {
			customRule.Condition = option.DefaultCondition
		}
		if customRule.Condition != "or" && customRule.Condition != "and" {
			myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errInvalidRuleCond, customRule.Name, customRule.Condition))
		}
		// 处理内部的 Detail
		for i, detail := range customRule.Details {
			// 先处理 DSL，DSL 权重最高
			if detail.DSL != "" {
				program, err := myWaf.env.Compile(detail.DSL)
				if err != nil {
					myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errCompileDSLExpr, detail.DSL, err.Error()))
					continue
				}
				customRule.Details[i].DslProgram = program
				continue
			}
			// 检查 DSL 和 regPattern 是否都为空
			// point 到这里的话，说明 DSL 已经为空了，只需要检查 regPattern 是否为空即可（这里是优化项）
			if detail.RegPattern == "" {
				myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errInvalidYAMLRule, customRule.Name, "DSL and pattern cannot be empty"))
				continue
			}

			// 检查 Method 是否是有效的，如果不是则默认置为 UNDEFINED
			if !isValidMethod(detail.Method) {
				detail.Method = request.UNDEFINED
			}

			// 如果 Method 有问题，那就默认全检测，顺便给个提示
			if detail.Method == request.UNDEFINED {
				detail.Method = request.ALL
				myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errInvalidYAMLRule, customRule.Name, "Method may be wrong"))
			}

			// 编译 regPattern
			regex, err := regexp.Compile(detail.RegPattern)
			if err != nil {
				myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errRegPattern, detail.RegPattern, err))
			}
			customRule.Details[i].RegExp = regex
		}
	}
	// 请求 cache 初始化，设置有效时间和
	myWaf.cache = cache.New(15*time.Minute, 20*time.Minute)
	// 响应体模板进行设置，先设置响应码
	if opt.Response.Status != 0 {
		respStatus = opt.Response.Status
	}
	// 再从文件设置响应体
	if opt.Response.HTMLFile != "" {
		htmlFile, err := os.ReadFile(opt.Response.HTMLFile)
		if err != nil {
			myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errReadFile, htmlFile, err))
		}
		customRespHTMLTemplate = string(htmlFile)
	}
	// 如果文件没有设置，但是直接给了 HTML 代码，那就用它 HTML 代码
	if customRespHTMLTemplate == "" && opt.Response.HTML != "" {
		customRespHTMLTemplate = opt.Response.HTML
	}
	// 别忘了将 opt 赋值给实例 myWaf 中的成员
	myWaf.opt = opt
	// 获取威胁数据库，将 threatData 初始化
	err = myWaf.getResource()
	if err != nil {
		myWaf.error(zapcore.PanicLevel, fmt.Sprintf(errResources, err))
	}
	// 创建额外的协程来执行 Falco 事件
	go myWaf.handleFalcoEvents()
	return myWaf
}

// getResource 表示从远程获取威胁数据库
func (myWaf *MyWaf) getResource() error {
	var isUpdated bool

	// 检查数据库是否是最新的
	isUpdated, err := threat.IsUpdated()
	// 报错为文件的读取问题
	if err != nil {
		isUpdated = false
	}
	// 如果当前是最新的（同一天），那么就要检查本地文件和远程的 md5 是否匹配
	if isUpdated {
		myWaf.logger.Debug("verifying dataset...")
		// todo 验证远程 MD5 和本地威胁库文件 MD5 是否相同
	}

	// 正常在 Linux 下启动时的情况
	if !isUpdated && !myWaf.opt.NoUpdateCheck && !myWaf.opt.InMemory {
		myWaf.logger.Debug("downloading dataset...")
		// todo 等 threat.Get 后面远程没有问题了，就要取消注销
		//err := threat.Get()
		//if err != nil {
		//	return err
		//}
	}

	// 创建内存变量
	threatFiles := make(map[string][]byte)
	// 在虚拟环境下的情况（InMemory 开启），将远程的威胁数据库直接读到内存中。
	if myWaf.opt.InMemory {
		myWaf.logger.Debug("downloading datasets in memory...")
		// 先请求远程仓库
		resp, err := http.Get(threat.DbURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		// 使用 compress 高性能压缩库的 zstd 算法
		zstdReader, err := zstd.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer zstdReader.Close()
		// 用标准 tar 库来解压文件
		tarReader := tar.NewReader(zstdReader)
		// 循环遍历 tar 中所有的文件
		for {
			// 先获取文件头部
			tarHeader, err := tarReader.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			// 如果不是标准的压缩包文件类型，那么直接跳过
			if tarHeader.Typeflag != tar.TypeReg {
				continue
			}
			// 读取当前文件内容
			fileContent, err := io.ReadAll(tarReader)
			if err != nil {
				return err
			}
			threatFiles[tarHeader.Name] = fileContent
		}
	}

	// 初始化威胁数据库结构体
	myWaf.threatData.Data = make(map[threat.Threat]string)

	// 初始化各种威胁数据库
	for _, threatType := range threat.List() {
		// 创建局部变量
		var err error
		var content []byte
		// 获取文件名（正常 Linux 环境获取完整文件路径）
		path, err := threatType.Filename(!myWaf.opt.InMemory)
		if err != nil {
			return err
		}
		// 如果设置了从 Memory 中读取，那么就从上面的变量中获取
		// 如果没有，那就先从文件中读取，文件不存在则从远程源获取到本地文件再读取，如果都不行就直接 return。
		// 如果不是文件不存在的错误，那说明是意料之外的错误，要直接返回。
		if myWaf.opt.InMemory {
			content = threatFiles[path]
		} else {
			content, err = os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					//err := threat.Get()
					//if err != nil {
					//	return err
					//}
					// 再次尝试从文件中读取，还不行的话就抛出吧
					content, err = os.ReadFile(path)
					if err != nil {
						return err
					}
				} else {
					return err
				}
				return err
			}
		}
		// 内容成功读取后存入变量中
		// note 有些文本末尾会有换行符，换行分割会导致产生空字符串存入威胁数据库中，因此需要去除掉
		myWaf.threatData.Data[threatType] = strings.TrimRight(string(content), "\n")
		// 内容已经存入，接下来要将其解析并存放到结构体变量中
		err = myWaf.processResource(threatType)
		if err != nil {
			return err
		}
	}
	return nil
}

// processResource 将每种威胁的纯文本规则进行处理，主要是对其初始化和反序列化，以将其转换成对应的结构体变量
// point 对于由软件官方提供的威胁库，不需要做过多的健壮性处理。而对外给用户自定义的（例如 YAML），那么就要使用 validator 进行规范。
func (myWaf *MyWaf) processResource(threatType threat.Threat) error {
	var err error

	// 如果配置选项是详细记录，那么将每次处理的行为进行记录
	if myWaf.opt.Verbose {
		threatCategory := threatType.ToString()
		count, err := threatType.Count()
		if err != nil {
			return err
		}
		filename, err := threatType.Filename(false)
		if err != nil {
			return err
		}
		myWaf.logger.Debug("load datasets",
			zap.String("category", threatCategory),
			zap.Int("count", count),
			zap.String("filename", filename))
	}

	// note 针对不同的攻击类型进行处理
	switch threatType {
	case threat.CommonWebAttack:
		myWaf.threatData.Cwa = &model.CWA{}
		// 反序列化
		err = sonic.Unmarshal([]byte(myWaf.threatData.Data[threatType]), &myWaf.threatData.Cwa)
		if err != nil {
			return err
		}
		// 将 CWA 中的 Rule 编译成正则表达式
		for i, filter := range myWaf.threatData.Cwa.Filters {
			var err error
			myWaf.threatData.Cwa.Filters[i].Pattern, err = regexp.Compile(filter.Rule)
			if err != nil {
				return err
			}
		}
	case threat.CVE:
		myWaf.threatData.Cve = &model.CVE{}
		// 先通过调用函数解析
		err = sonic.Unmarshal([]byte(myWaf.threatData.Data[threatType]), &myWaf.threatData.Cve)
		if err != nil {
			return err
		}
		// 如果模板没有解析出来，那就要报错
		if myWaf.threatData.Cve.Templates == nil || len(myWaf.threatData.Cve.Templates) == 0 {
			return fmt.Errorf("the CVE templates didn't exist")
		}
		// 遍历每一条 CVE
		for _, template := range myWaf.threatData.Cve.Templates {
			// 遍历每一个 CVE 中的具体规则
			for _, oneReq := range template.Requests {
				// 将 Raw 和 Path 解析成 url.URL
				// 如果 Path 和 Raw 都不为空，那么 Path 会覆盖 Raw（个人觉得 Path 给的信息要比 Raw 更详细）
				oneReq.Url = make([]*url.URL, 0)
				if len(oneReq.Raw) > 0 {
					for _, oneRaw := range oneReq.Raw {
						// bufio 库是 io 的封装，为磁盘读取内置了一个缓冲。
						parsedRaw := bufio.NewReader(normalizeRawStringReader(oneRaw))
						// question 这个底层方法只支持 HTTP/1.x 的解析，HTTP/2 以上的版本需要额外使用 golang.org/x/net/http2.
						parsedReq, err := http.ReadRequest(parsedRaw)
						if err != nil {
							continue
						}
						oneReq.Url = append(oneReq.Url, parsedReq.URL)
					}
				}
				if len(oneReq.Path) > 0 {
					for _, onePath := range oneReq.Path {
						parsedURL, err := url.ParseRequestURI(
							strings.TrimPrefix(
								strings.Trim(onePath, `"`), "{{BaseURL}}",
							),
						)
						if err != nil {
							continue
						}
						oneReq.Url = append(oneReq.Url, parsedURL)
					}
				}
				// 遍历 Matchers，将内部的一些变量进行初始化
				for _, matcher := range oneReq.Matchers {
					switch matcher.Type {
					// 和主应用共用同一个 DSL 环境
					case "dsl":
						for _, oneDSL := range matcher.DSL {
							program, err := myWaf.env.Compile(oneDSL)
							if err != nil {
								continue
							}
							matcher.DSLPrograms = append(matcher.DSLPrograms, program)
						}
					case "regex":
						for _, oneRegex := range matcher.Regex {
							regPattern, err := regexp.Compile(oneRegex)
							if err != nil {
								continue
							}
							matcher.RegPatterns = append(matcher.RegPatterns, regPattern)
						}
					}
					if oneReq.MatchersCondition == "and" || oneReq.MatchersCondition == "or" {
						matcher.Condition = oneReq.MatchersCondition
					}
				}
			}
		}
	case threat.BadCrawler:
		// 根据换行符将恶意 IP 文件进行拆分
		ipRegPatterns := strings.Split(myWaf.threatData.Data[threatType], "\n")
		myWaf.threatData.BadCrawler = make([]*regexp.Regexp, len(ipRegPatterns))
		for i, regPattern := range ipRegPatterns {
			var err error
			myWaf.threatData.BadCrawler[i], err = regexp.Compile(regPattern)
			if err != nil {
				return err
			}
		}
	// 总体逻辑和 threat.BadCrawler 的处理逻辑一样
	case threat.MaliciousCommand:
		mcRegPatterns := strings.Split(myWaf.threatData.Data[threatType], "\n")
		myWaf.threatData.MaliciousCommand = make([]*regexp.Regexp, len(mcRegPatterns))
		for i, regPattern := range mcRegPatterns {
			var err error
			myWaf.threatData.MaliciousCommand[i], err = regexp.Compile(regPattern)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
