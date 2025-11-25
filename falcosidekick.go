// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/11/1 17:07
// @Description    : 对接 Falcosidekick 的结构体以及方法
// -------------------------------------------
package MyWaf

import (
	"bytes"
	"github.com/bytedance/sonic"
	"github.com/daniel-hutao/spinlock"
	"github.com/panjf2000/ants/v2"
	"go.uber.org/zap/zapcore"
	"io"
	"net/http"
	"slices"
	"time"
)

// falcoEvent 是对接 Falcosidekick 的事件结构体，被序列化成 JSON 后发送给 Falcosidekick HTTP 接收端
// 事件的格式详见：https://falco.org/docs/concepts/outputs/channels/
type falcoEvent struct {
	Output   string `json:"output"`   // 格式化后的事件概述
	Priority string `json:"priority"` // 优先级，有 8 个等级
	Rule     string `json:"rule"`     // 规则名
	Time     string `json:"time"`
	// output_fields 内的内容为自定义内容
	OutputFields struct {
		Caller         string `json:"myWaf.caller"`
		ID             string `json:"myWaf.id"`
		Threat         string `json:"myWaf.threat"`
		ListenAddr     string `json:"myWaf.listen_addr"`
		RequestBody    string `json:"request.body"`
		RequestHeaders string `json:"request.headers"`
		RequestIPAddr  string `json:"request.ip_addr"`
		RequestMethod  string `json:"request.method"`
		RequestPath    string `json:"request.path"`
	} `json:"output_fields"`
}

// falcoSidekick 为存放多个 falcoEvent 的结构体，其有自旋锁来保证并发安全
type falcoSidekick struct {
	events []*falcoEvent
	sl     spinlock.SpinLock
}

// handleFalcoEvents 每隔 5s 调用一次 sendFalcoEvents 来发送事件
func (myWaf *MyWaf) handleFalcoEvents() {
	// 检查是否配置了 Falcosidekick
	if myWaf.opt.FalcosidekickURL == "" {
		return
	}
	// 初始化 Ticker
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	// 每 5 秒完成：上锁、发送、解锁
	for range ticker.C {
		myWaf.falcoSidekick.sl.Lock()
		if len(myWaf.falcoSidekick.events) > 0 {
			myWaf.sendFalcoEvents()
		}
		myWaf.falcoSidekick.sl.Unlock()
	}
}

// sendFalcoEvents 向 Falcosidekick 发送 Falco 事件。使用 goroutine pool 来并发发送事件
func (myWaf *MyWaf) sendFalcoEvents() {
	// 创建工作线程数
	eventCount := len(myWaf.falcoSidekick.events)
	workerNum := eventCount / 2
	if workerNum == 0 {
		workerNum = 1
	}
	// 创建协程池
	routinePool, _ := ants.NewPool(workerNum)
	// 循环遍历每一个事件，每有一个事件就交给一个协程处理
	for _, event := range myWaf.falcoSidekick.events {
		err := routinePool.Submit(func() {
			// 序列化
			payload, err := sonic.Marshal(event)
			if err != nil {
				myWaf.error(zapcore.ErrorLevel, err.Error())
			}
			// 发送数据
			post, err := http.Post(myWaf.opt.FalcosidekickURL, "application/json", bytes.NewBuffer(payload))
			if err != nil {
				myWaf.error(zapcore.ErrorLevel, err.Error())
			}
			// HTTP Close 异常处理
			defer func(Body io.ReadCloser) {
				err := Body.Close()
				if err != nil {
					myWaf.error(zapcore.ErrorLevel, err.Error())
				}
			}(post.Body)
		})
		if err != nil {
			myWaf.error(zapcore.ErrorLevel, err.Error())
		}
	}
	// 给 2s 等待协程池任务处理完毕
	err := routinePool.ReleaseTimeout(2 * time.Second)
	if err != nil {
		myWaf.error(zapcore.ErrorLevel, err.Error())
	}
	// 移除当前数组中的所有数据
	myWaf.falcoSidekick.events = slices.Delete(myWaf.falcoSidekick.events, 0, eventCount)
}
