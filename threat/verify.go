// Package threat -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/17 11:08
// @Description    : 检查文件的完整性，通过本地文件与仓库文件的 MD5 校验和进行对比。
// -------------------------------------------
package threat

import (
	"bufio"
	"fmt"
	"github.com/codingsince1985/checksum"
	"net/http"
	"path/filepath"
	"strings"
)

// Verify 检查文件的完整性，通过本地文件与仓库文件的 MD5 校验和进行对比。
// 如果有不匹配的，则返回对应的文件名，否则返回空字符串和报错。
func Verify() error {
	md5Sums, err := fetchMD5Sums()
	if err != nil {
		return err
	}
	return verifyChecksums(md5Sums)
}

// fetchMD5Sums 从远程仓库中获取 MD5 校验和，同时将结果以 map 形式返回。
// 其中 key 为文件名，value 为对应的 MD5 校验和。
func fetchMD5Sums() (map[string]string, error) {
	// 1. 初始化 map 用于存储 MD5 校验和
	md5sums := make(map[string]string)

	// 2. 发送 HTTP GET 请求获取校验和文件
	resp, err := http.Get(MD5SumURL)
	if err != nil {
		return nil, fmt.Errorf(errFetchMD5, err)
	}
	defer resp.Body.Close()

	// 3. 逐行读取文件内容，有问题报错
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		// 每行根据分隔符（空格或制表符等）拆分成两部分
		parts := strings.Fields(line)
		if len(parts) == 2 {
			filename, md5 := parts[1], parts[0]
			// 跳过数据库压缩文件的校验
			if filename == DbFilename {
				continue
			}
			md5sums[filename] = md5
		}
	}

	// 4. 检查扫描过程中是否有错误
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf(errFetchMD5, err)
	}

	return md5sums, nil
}

// verifyChecksums 比较从远程获取的 MD5 校验和与本地文件的校验和。
// 它接受一个包含文件名和对应 MD5 校验和的 map 作为输入。
func verifyChecksums(md5sums map[string]string) error {
	// 遍历所有威胁类型
	for _, threat := range List() {
		// 获取威胁类型对应的文件路径
		filePath, err := threat.Filename(true)
		if err != nil {
			return err
		}
		// 获取文件并计算其 MD5 校验和
		localMD5, err := checksum.MD5sum(filePath)
		if err != nil {
			return err
		}
		filename := filepath.Base(filePath)
		// 比较本地计算的 MD5 与远程获取的 MD5
		if localMD5 != md5sums[filename] {
			return fmt.Errorf(errChecksumMismatch, filename)
		}
	}

	return nil
}
