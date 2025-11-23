// Package example -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/14 14:43
// @Description    : todo
// -------------------------------------------
package example

import (
	"MyWaf"
	"MyWaf/option"
	"MyWaf/request"
	"MyWaf/threat"
	"net/http"
)

var myHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("hello world"))
})

func main() {
	telerMiddleware := MyWaf.New(option.Options{
		Excludes: []threat.Threat{
			threat.BadReferrer,
			threat.BadCrawler,
		},
		Whitelists: []string{
			`request.Headers matches "(curl|Go-http-client|okhttp)/*" && threat == BadCrawler`,
			`request.URI startsWith "/wp-login.php"`,
			`request.IP in ["127.0.0.1", "::1", "0.0.0.0"]`,
			`request.Headers contains "authorization" && request.Method == "POST"`,
		},
		CustomsFromFile: "/path/to/custom/rules/*.yaml",
		Customs: []option.Rule{
			{
				Name:      "Log4j Attack",
				Condition: "or",
				Details: []option.Detail{
					{
						Method: request.GET,
						// if Method is not set or invalid, defaulting to request.GET.
						Element: request.Body,
						// you can use request.Any: it useful when you want to
						// match against multiple elements of the request at once,
						// rather than just a single element.
						RegPattern: `\$\{.*:\/\/.*\/?\w+?\}`,
					},
				},
			},
		},
		LogFile: "/tmp/teler.log",
	})

	app := telerMiddleware.Handler(myHandler)
	go func() {
		println("Listening on 3000")
	}()
	http.ListenAndServe("0.0.0.0:3000", app)
}
