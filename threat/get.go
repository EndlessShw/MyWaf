// Package threat -----------------------------
// @author         : EndlessShw
// @time           : 2025/9/15 16:20
// @Description    : 获取 threat 规则文件
// -------------------------------------------
package threat

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/otiai10/copy"
)

// Get 本地或远程获取 threat 规则文件
// Get 本地是从 tmp 目录下复制过来；远程是从仓库中获取
// todo “是否使用用户指定的规则文件” 的逻辑交给上层处理
func Get() error {
	// 判断当前用户下的规则文件路径是否存在。存在的话就先全部删除然后创建路径并复制。不存在就不需要删除。
	threatLocation, err := location()
	if err != nil {
		return err
	}
	// 路径存在时要先删除
	// point RemoveAll 如果路径不存在，那就无事发生（注意不会返回 nil）
	err = os.RemoveAll(threatLocation)
	if err != nil {
		return err
	}
	err = os.MkdirAll(threatLocation, 0755)
	if err != nil {
		return err
	}
	// 然后将 /tmp 下的文件转移到 .cache 下
	err = getFromLocal()
	if err != nil {
		// todo 如果本地获取不到，那就要调用远程来获取
		// todo 获取完后 tmp 目录下也拷贝一份
		//tmpDst, err := tmpLocation()
		//if err != nil {
		//	return err
		//}
	}
	return nil
}

// location 返回规则文件的所在位置
func location() (string, error) {
	// 获取当前用户的默认缓存地址
	userCacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	// 拼接上 threat 地址
	return filepath.Join(userCacheDir, ThreatPath), nil
}

// tmpLocation 返回 /tmp 下规则文件路径
// 同时完成创建操作
func tmpLocation() (string, error) {
	date := time.Now().Format("20060102")
	tmpLoc := filepath.Join(os.TempDir() + fmt.Sprintf(TmpDirSuffix, date))
	// point 注意如果路径已经存在的话，MKdir 不会做任何事情，返回 nil
	err := os.MkdirAll(tmpLoc, 0755)
	// 当且仅当创建失败的原因是 tmp 路径获取不到时，返回空
	if err != nil && !os.IsExist(err) {
		return "", err
	}
	return tmpLoc, nil
}

// getFromLocal 从 tmp 路径将文件拷贝到 .cache 下
func getFromLocal() error {
	tmpLoc, err := tmpLocation()
	if err != nil {
		return err
	}
	threatLoc, err := location()
	if err != nil {
		return err
	}
	// point https://github.com/otiai10/copy 文件夹拷贝库
	err = copy.Copy(tmpLoc, threatLoc)
	if err != nil {
		return err
	}
	return nil
}

// IsUpdated 检测当前威胁库是否是最新的
func IsUpdated() (bool, error) {
	// 初始化返回的变量
	var isUpdated bool
	// 获取规则文件状态
	loc, err := location()
	if err != nil {
		return false, err
	}
	dir, err := os.Stat(loc)
	if err != nil {
		return false, err
	}
	// 定义时间格式，目前定位到天
	// todo 这里可以通过配置文件，对外设定日或月
	timeLayout := "2006-01-02"
	// 获取规则库文件的修改时间和当前的时间
	modTime := dir.ModTime().Format(timeLayout)
	nowTime := time.Now().Format(timeLayout)

	// 检查两个日期的天数是否相同
	isUpdated = modTime == nowTime

	return isUpdated, nil
}
