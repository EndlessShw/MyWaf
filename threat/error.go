// Package threat -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/28 0:01
// @Description    : threat 包下的错误提示
// -------------------------------------------
package threat

const (
	errFilepath         = "unable to get file path location of given %s threat type"
	errFetchMD5         = "unable to fetch MD5SUMS from remote repository: %v"
	errChecksumMismatch = "checksum mismatch for file %s"
)
