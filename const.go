// Package MyWaf -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/19 0:10
// @Description    : 存放一些上层/全局用到的参数
// -------------------------------------------
package MyWaf

import "net/http"

const (
	xMyWafReqId      = "X-My-Waf-Req-Id"
	XMyWafMsg        = "X-My-Waf-Msg"
	xMyWafThreatType = "X-My-Waf-Threat"
	// DefaultRespStatus 表示 RespHTMLResponse 默认适用的 HTTPStatus。
	DefaultRespStatus = http.StatusForbidden
	// DefaultRespHTMLResponse 中 ID、message 和 threat 根据分析时的结果填充
	DefaultRespHTMLResponse = `<!DOCTYPE html>
<html>
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>403 Forbidden</title>
</head>
<body style="width: 500px; margin:0 auto; text-align:left; font-size: 12pt; font-family: monospace; padding: 1em;">
	<h1>403 Forbidden</h1>
	<p>We're sorry, but your request has been denied for security reasons.</p>
	<p>If you feel this is an error, please contact customer support for further assistance.</p>
	<p><a href="#" onclick="javascript:back();">Go back</a>.</p>
  <hr>
  <p>Req-Id: {{ID}} <!-- | Msg: {{message}} (Threat: {{threat}}) --></p>
</body>
<script type="text/javascript">function back(){const o=document.referrer;o&&new URL(o).hostname===window.location.hostname?history.back():window.location.href="/"}</script>
</html>
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->`
)
