package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const hostsFile = `C:\Windows\System32\drivers\etc\hosts`
const customMarker = "# === LINUX.DO OPTIMIZED IP ==="

var entries = []string{
	"172.66.166.61 linux.do",
	"172.66.166.61 cdn.linux.do",
	"172.66.166.61 cdn3.linux.do",
}

var (
	advapi32                     = syscall.NewLazyDLL("advapi32.dll")
	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	procFreeSid                  = advapi32.NewProc("FreeSid")
	procCheckTokenMembership     = advapi32.NewProc("CheckTokenMembership")

	shell32           = syscall.NewLazyDLL("shell32.dll")
	procShellExecuteW = shell32.NewProc("ShellExecuteW")
)

func main() {
	// 1. 权限管理：检查是否有管理员权限，如果没有则提权重启
	if !isAdmin() {
		fmt.Println("当前无管理员权限，尝试以管理员身份重新启动...")
		elevate()
		return
	}

	fmt.Println("成功获取管理员权限。")

	// 2. 保证退出时清理 Hosts 文件
	defer func() {
		fmt.Println("正在清理并还原 Hosts 文件...")
		removeHosts()
		fmt.Println("程序已安全退出。")
	}()

	// 清理之前残留的记录并写入新记录（防止异常退出导致的冗余）
	removeHosts()
	if err := addHosts(); err != nil {
		fmt.Printf("修改 Hosts 文件失败: %v\n", err)
		return
	}
	fmt.Println("Hosts 文件修改成功。")

	// 3. 浏览器引导：寻找并以 QUIC 参数启动 Chrome/Edge
	launchBrowser()

	// 4. 生命周期管理：捕获退出信号，阻塞程序并保持运行
	fmt.Println("\n服务运行中... 请不要直接关闭窗口，按 Ctrl+C 退出以清理环境。")
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}

// isAdmin 检查当前是否以管理员系统权限运行
func isAdmin() bool {
	var sid *syscall.SID
	var auth = [6]byte{0, 0, 0, 0, 0, 5} // SECURITY_NT_AUTHORITY

	ret, _, _ := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&auth)),
		2,
		32,  // SECURITY_BUILTIN_DOMAIN_RID
		544, // DOMAIN_ALIAS_RID_ADMINS
		0, 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&sid)))
	if ret == 0 {
		return false
	}
	defer procFreeSid.Call(uintptr(unsafe.Pointer(sid)))

	var isMember int32
	ret, _, _ = procCheckTokenMembership.Call(
		0,
		uintptr(unsafe.Pointer(sid)),
		uintptr(unsafe.Pointer(&isMember)))
	if ret == 0 {
		return false
	}
	return isMember != 0
}

// elevate 调用 Windows API 以管理员权限运行当前程序
func elevate() {
	verb := "runas"
	exe, err := os.Executable()
	if err != nil {
		fmt.Println("无法获取可执行文件路径: ", err)
		return
	}
	cwd, _ := os.Getwd()
	args := joinEscapedArgs(os.Args[1:])

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString(cwd)
	argPtr, _ := syscall.UTF16PtrFromString(args)

	var showCmd int32 = 1 // SW_NORMAL

	r, _, callErr := procShellExecuteW.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		uintptr(showCmd))

	if r <= 32 {
		if callErr != nil && callErr != syscall.Errno(0) {
			fmt.Printf("提权启动失败 (code=%d): %v\n", r, callErr)
		} else {
			fmt.Printf("提权启动失败 (code=%d)\n", r)
		}
	}
}

func joinEscapedArgs(args []string) string {
	if len(args) == 0 {
		return ""
	}

	escaped := make([]string, 0, len(args))
	for _, arg := range args {
		escaped = append(escaped, syscall.EscapeArg(arg))
	}

	return strings.Join(escaped, " ")
}

// addHosts 向系统 Hosts 文件中写入映射及标识符
func addHosts() error {
	f, err := os.OpenFile(hostsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString("\n" + customMarker + "\n"); err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := f.WriteString(entry + "\n"); err != nil {
			return err
		}
	}
	if _, err := f.WriteString(customMarker + "\n"); err != nil {
		return err
	}
	return nil
}

// removeHosts 通过匹配标识符，删除之前写入的 Hosts 内容
func removeHosts() {
	content, err := os.ReadFile(hostsFile)
	if err != nil {
		fmt.Printf("读取 Hosts 文件时遇到错误: %v\n", err)
		return
	}

	lines := strings.Split(string(content), "\n")
	var newLines []string

	// 遍历每一行，采用绝对值匹配过滤，避免开关逻辑导致未闭合时误删正常内容
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// 过滤标记行
		if trimmed == customMarker {
			continue
		}

		// 过滤我们自己注入的数据行
		isEntry := false
		for _, entry := range entries {
			if trimmed == entry {
				isEntry = true
				break
			}
		}

		if !isEntry {
			newLines = append(newLines, line)
		}
	}

	// 写入时去除最后可能的空行，防止一直增加空行
	result := strings.TrimRight(strings.Join(newLines, "\n"), "\r\n") + "\n"
	if err := os.WriteFile(hostsFile, []byte(result), 0644); err != nil {
		fmt.Printf("恢复 Hosts 文件时遇到错误: %v\n", err)
	}
}

// launchBrowser 按照常见路径查找浏览器并附带参数启动
func launchBrowser() {
	programFiles := os.Getenv("ProgramFiles")
	programFilesX86 := os.Getenv("ProgramFiles(x86)")

	browsers := []string{
		filepath.Join(programFiles, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(programFilesX86, `Google\Chrome\Application\chrome.exe`),
		filepath.Join(programFilesX86, `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(programFiles, `Microsoft\Edge\Application\msedge.exe`),
	}

	args := []string{
		"--enable-quic",
		"--origin-to-force-quic-on=linux.do:443,cdn.linux.do:443,cdn3.linux.do:443",
		"https://linux.do",
	}

	var browserPath string
	for _, b := range browsers {
		if _, err := os.Stat(b); err == nil {
			browserPath = b
			break
		}
	}

	if browserPath == "" {
		fmt.Println("警告：未在默认位置找到 Chrome 或 Edge 浏览器。请手动打开浏览器测试。")
		return
	}

	cmd := exec.Command(browserPath, args...)
	if err := cmd.Start(); err != nil {
		fmt.Printf("启动浏览器 (%s) 失败: %v\n", browserPath, err)
	} else {
		fmt.Println("已成功启动浏览器，正在通过 HTTP/3 访问 linux.do")
	}
}
