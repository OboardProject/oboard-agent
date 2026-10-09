// Package runtimesecurity inspects only caller-owned OBoard resources. It never
// executes a command, accepts a remote path or exports file/environment values.
package runtimesecurity

import (
	"context"
	"fmt"
	"github.com/OboardProject/oboard-agent/internal/model"
	"github.com/OboardProject/oboard-agent/internal/securefile"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Target struct {
	ID, Path                            string
	Directory, Public, Optional, Socket bool
	Repairable                          bool
}
type Kernel struct {
	UID                   int    `json:"uid"`
	GID                   int    `json:"gid"`
	EffectiveCapabilities string `json:"effective_capabilities,omitempty"`
	IdentitySupported     bool   `json:"identity_supported"`
	SensitiveArguments    bool   `json:"sensitive_arguments"`
	SensitiveEnvironment  bool   `json:"sensitive_environment"`
	LocalAPI              string `json:"local_api"`

	Mode              string `json:"mode"`
	Supported         bool   `json:"supported"`
	NoNewPrivileges   bool   `json:"no_new_privileges"`
	Dumpable          bool   `json:"dumpable"`
	CoreDumpsDisabled bool   `json:"core_dumps_disabled"`
}
type Input struct {
	Mode, LocalPolicy string
	Revision          int64
	Targets           []Target
	Kernel            *Kernel
	Encrypted         bool
}

func Inspect(ctx context.Context, input Input) model.RuntimeSecurityReport {
	now := time.Now().UTC()
	report := model.RuntimeSecurityReport{Revision: input.Revision, DesiredMode: input.Mode, ActualMode: "unknown", State: "partial", Platform: runtime.GOOS, Supported: runtime.GOOS == "linux" && input.Kernel != nil && input.Kernel.Supported, Phase: "checked", LocalPolicy: input.LocalPolicy, CheckedAt: now, Capabilities: []string{"managed_permissions", "bounded_inspection", "bound_state_encryption", "signed_binary_integrity", "managed_permission_repair"}, Checks: []model.RuntimeSecurityCheck{}}
	add := func(id, category, status, severity, message, remedy string) {
		report.Checks = append(report.Checks, model.RuntimeSecurityCheck{ID: id, Category: category, Status: status, Supported: status != "unsupported", Severity: severity, CheckedAt: now, Message: message, Remedy: remedy})
	}
	for i, target := range input.Targets {
		if i >= 32 || ctx.Err() != nil {
			add("inspection_budget", "filesystem", "unknown", "warning", "检查达到资源上限", "稍后重新检查")
			break
		}
		if runtime.GOOS == "windows" {
			add(target.ID, "filesystem", "unsupported", "info", "当前检查器不将 POSIX 权限位作为 Windows ACL 证据", "由管理员核对 Windows ACL")
			continue
		}
		info, err := os.Lstat(target.Path)
		if os.IsNotExist(err) && target.Optional {
			add(target.ID, "filesystem", "unknown", "info", "资源尚未创建", "资源创建后重新检查")
			continue
		}
		if err != nil {
			add(target.ID, "filesystem", "unknown", "warning", "无法检查受管资源", "检查资源是否存在及 Agent 访问权限")
			continue
		}
		unsafe := info.Mode()&os.ModeSymlink != 0 || unexpectedOwner(info)
		if target.Directory {
			unsafe = unsafe || !info.IsDir()
		} else if target.Socket {
			unsafe = unsafe || info.Mode()&os.ModeSocket == 0
		} else {
			unsafe = unsafe || !info.Mode().IsRegular()
		}
		if target.Public {
			unsafe = unsafe || info.Mode().Perm()&0022 != 0
		} else {
			expected := os.FileMode(0600)
			if target.Directory {
				expected = 0700
			}
			unsafe = unsafe || info.Mode().Perm() != expected || unexpectedLinks(info)
		}
		if unsafe {
			add(target.ID, "filesystem", "failed", "high", "受管资源类型或访问权限不安全", "修复权限，敏感目录 0700、文件 0600；符号链接或异常所有者须由主机管理员处理")
			report.Checks[len(report.Checks)-1].AutoFix = target.Repairable && repairableOwner(info) && (info.IsDir() == target.Directory)
		} else {
			add(target.ID, "filesystem", "passed", "info", "受管资源访问权限符合要求", "")
		}
	}
	if executable, err := os.Executable(); err == nil && len(executable) <= 384 {
		add("process_executable", "process", "passed", "info", "Agent 可执行文件："+executable, "软件名称与正常安装路径本身不属于凭据泄露")
	}
	if runtime.GOOS == "linux" {
		if comm, err := securefile.Read("/proc/self/comm", 64); err == nil {
			add("process_name", "process", "passed", "info", "Agent 进程名称："+strings.TrimSpace(string(comm)), "不隐藏或伪造软件身份")
		}
	}
	// Inspect only this process. No full argv or environment is returned.
	exposure := false
	for _, arg := range os.Args[1:] {
		lower := strings.ToLower(arg)
		if sensitiveArgument(lower) {
			exposure = true
		}
	}
	if exposure {
		add("process_arguments", "process", "failed", "high", "启动参数中存在疑似敏感值", "使用受保护的配置文件传递凭据")
	} else {
		add("process_arguments", "process", "passed", "info", "未发现凭据型启动参数", "")
	}
	exposure = false
	for _, env := range os.Environ() {
		name, _, _ := strings.Cut(env, "=")
		name = strings.ToUpper(name)
		if strings.Contains(name, "TOKEN") || strings.Contains(name, "PASSWORD") || strings.Contains(name, "SECRET") || strings.Contains(name, "PRIVATE_KEY") {
			exposure = true
		}
	}
	if exposure {
		add("process_environment", "process", "warning", "warning", "进程继承了可能包含凭据的环境变量", "检查服务环境；移除安装或调试遗留凭据")
	} else {
		add("process_environment", "process", "passed", "info", "未发现凭据型环境变量", "")
	}
	if runtime.GOOS != "linux" {
		add("process_identity", "process", "unsupported", "info", "当前平台不支持 Linux 进程权限检测", "")
	} else {
		status, err := securefile.Read("/proc/self/status", 64<<10)
		if err != nil {
			add("process_identity", "process", "unknown", "warning", "无法读取 Agent 进程权限", "检查容器是否允许读取自身进程状态")
		} else {
			for _, line := range strings.Split(string(status), "\n") {
				name, value, ok := strings.Cut(line, ":")
				if !ok {
					continue
				}
				base := 10
				switch name {
				case "Uid", "Gid":
				case "CapEff", "CapBnd", "CapAmb":
					base = 16
				default:
					continue
				}
				fields := strings.Fields(value)
				valid := len(fields) > 0 && len(fields) <= 4
				for _, field := range fields {
					if _, err := strconv.ParseUint(field, base, 64); err != nil {
						valid = false
					}
				}
				if valid {
					add("process_"+strings.ToLower(name), "process", "passed", "info", fmt.Sprintf("Agent %s：%s", name, strings.Join(fields, " / ")), "此项记录实际权限，不表示权限已缩减")
				}
			}
			if strings.Contains(string(status), "Uid:\t0\t") {
				add("process_identity", "process", "passed", "info", "Agent 以 root 运行以提供受管更新和网络操作", "本检查不修改 Agent UID 或能力，远程操作仍受本地策略限制")
			} else {
				add("process_identity", "process", "passed", "info", "Agent 以非 root 身份运行", "")
			}
		}
	}
	if input.Encrypted {
		add("state_storage", "storage", "passed", "info", "Agent 私有 SSH 状态采用用途绑定的认证加密", "密钥与数据同机保存，不能抵御容器 root 或宿主机管理员")
	} else {
		add("state_storage", "storage", "passed", "info", "状态使用文件访问权限保护", "强化模式额外加密 Agent 私有 SSH 状态；内核及外部工具必需配置仍由权限保护")
	}
	if input.Kernel == nil {
		add("kernel_profile", "service", "unknown", "warning", "尚未取得运行内核的安全状态", "先更新内核并确认本地管理接口可用")
	} else if !input.Kernel.Supported {
		add("kernel_profile", "service", "unsupported", "info", "内核或当前平台不支持该强化配置", "")
	} else if input.Kernel.Mode == "enhanced" && input.Kernel.NoNewPrivileges && !input.Kernel.Dumpable && input.Kernel.CoreDumpsDisabled {
		report.ActualMode = "enhanced"
		add("kernel_profile", "service", "passed", "info", "运行内核已禁止新增权限及进程转储", "")
	} else {
		report.ActualMode = "standard"
		if input.Mode == "standard" {
			report.State = "standard"
		}
		status := "warning"
		if input.Mode == "standard" {
			status = "passed"
		}
		add("kernel_profile", "service", status, "info", "内核当前使用标准运行权限", "应用强化模式后需要受控重启并重新验证")
	}
	if input.Kernel != nil {
		k := input.Kernel
		if k.IdentitySupported {
			add("kernel_identity", "process", "passed", "info", fmt.Sprintf("内核 UID/GID：%d/%d，实际 CapEff：%s", k.UID, k.GID, k.EffectiveCapabilities), "权限值是实际观测，未统一删除网络能力")
		} else {
			add("kernel_identity", "process", "unsupported", "info", "内核未提供进程身份与能力证据", "")
		}
		if k.SensitiveArguments {
			add("kernel_arguments", "process", "failed", "high", "内核参数存在疑似敏感字段", "改用受保护的配置文件")
		} else if k.IdentitySupported {
			add("kernel_arguments", "process", "passed", "info", "未发现内核凭据型启动参数", "")
		}
		if k.SensitiveEnvironment {
			add("kernel_environment", "process", "warning", "high", "内核继承了疑似敏感环境变量", "移除服务环境中的安装凭据")
		}
		switch k.LocalAPI {
		case "unix":
			add("kernel_api_transport", "interface", "passed", "info", "内核管理接口使用 Unix Socket", "")
		case "tcp":
			add("kernel_api_transport", "interface", "failed", "high", "内核管理接口启用了 TCP 监听", "改为受限 Unix Socket；loopback 也可被其他本地用户访问")
		default:
			add("kernel_api_transport", "interface", "unknown", "warning", "无法确认内核管理接口类型", "")
		}
	}
	add("network_privileges", "service", "passed", "info", "保留现有网络能力和服务身份", "TUN、WireGuard、低端口及接口绑定不采用未经验证的统一降权")
	add("host_boundary", "process", "unsupported", "info", "共享内核无法阻止宿主机管理员观察容器进程", "普通用户文件权限、容器 root 和宿主机权限是不同边界")
	if input.Mode == "enhanced" {
		report.State = "partial"
		if runtime.GOOS != "linux" || (input.Kernel != nil && !input.Kernel.Supported) {
			report.State = "unsupported"
		} else if report.ActualMode == "enhanced" && input.Encrypted {
			report.State = "enhanced"
		}
		for _, check := range report.Checks {
			if check.Status == "failed" {
				report.State = "partial"
			}
		}
	}
	return report
}

// CheckManagedTree examines metadata only, without following links. Traversal
// stops at a fixed entry count and depth rather than scanning a filesystem.
func CheckManagedTree(ctx context.Context, path string) string {
	before, err := os.Lstat(path)
	if err != nil {
		return "unknown"
	}
	if !before.IsDir() || before.Mode().Perm() != 0700 || unexpectedOwner(before) {
		return "failed"
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return "unknown"
	}
	defer root.Close()
	after, err := root.Stat(".")
	if err != nil || !os.SameFile(before, after) {
		return "unknown"
	}
	queue := []string{"."}
	seen := 0
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return "unknown"
		}
		dir := queue[0]
		queue = queue[1:]
		file, err := root.OpenFile(dir, directoryFlags(), 0)
		if err != nil {
			return "unknown"
		}
		entries, err := file.ReadDir(129 - seen)
		file.Close()
		if err != nil && err != io.EOF && len(entries) == 0 {
			return "unknown"
		}
		for _, entry := range entries {
			seen++
			if seen > 128 {
				return "unknown"
			}
			name := filepath.Join(dir, entry.Name())
			info, err := root.Lstat(name)
			if err != nil {
				return "unknown"
			}
			if info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || unexpectedOwner(info) || unexpectedLinks(info) {
				return "failed"
			}
			if info.IsDir() {
				if strings.Count(name, string(filepath.Separator)) >= 3 {
					return "unknown"
				}
				queue = append(queue, name)
			}
		}
	}
	return "passed"
}

func sensitiveArgument(arg string) bool {
	name, _, _ := strings.Cut(strings.TrimLeft(strings.ToLower(arg), "-"), "=")
	switch strings.ReplaceAll(name, "-", "_") {
	case "token", "agent_token", "password", "passwd", "psk", "secret", "private_key":
		return true
	}
	return false
}

// InspectService reads one resolved OBoard unit, never arbitrary paths supplied
// in a task. Declarations are not treated as evidence of effective restrictions.
func InspectService(path, manager, id string, now time.Time) model.RuntimeSecurityCheck {
	result := model.RuntimeSecurityCheck{ID: id, Category: "service", Severity: "info", Status: "unknown", Supported: true, CheckedAt: now, Message: "服务定义尚未核实", Remedy: "核对受管服务定义和实际进程限制"}
	raw, err := securefile.Read(path, 64<<10)
	if err != nil {
		return result
	}
	for _, line := range strings.Split(string(raw), "\n") {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "password=") || strings.Contains(lower, "token=") || strings.Contains(lower, "private_key=") {
			result.Status = "warning"
			result.Severity = "high"
			result.Message = "服务定义中存在疑似凭据型参数或环境设置"
			result.Remedy = "使用受保护的配置文件，不在服务参数或环境中保存凭据"
			return result
		}
	}
	if manager == "openrc" {
		result.Status = "unsupported"
		result.Supported = false
		result.Message = "OpenRC 不提供 systemd 服务沙箱；内核原生限制单独验证"
	} else {
		result.Message = "已读取服务定义；沙箱声明不作为实际生效证据，内核限制单独验证"
	}
	return result
}
