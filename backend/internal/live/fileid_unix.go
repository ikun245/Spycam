//go:build unix

package live

import (
	"os"
	"syscall"
)

// fileID 返回文件 inode，用于识别 eve.json 是否已被轮转为新文件。
func fileID(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}
