//go:build !unix

package live

import "os"

// fileID 在非 Unix 平台不可用（服务只在 Linux 容器内运行），返回 0 时退化为按文件变短判断轮转。
func fileID(os.FileInfo) uint64 { return 0 }
