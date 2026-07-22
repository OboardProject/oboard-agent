package agent

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	managementAgentService = "oboard-agent"
	managementCoreService  = "oboard-sb"
	managementLogLines     = 120
)

// RunManagementConsole provides the user-facing `obag` command.
func RunManagementConsole(defaultConfigPath string, args []string, in io.Reader, out, errOut io.Writer) int {
	console := managementConsole{
		in:      bufio.NewReader(in),
		out:     out,
		errOut:  errOut,
		manager: serviceManager(),
	}
	console.configPath, console.config = loadManagementConfig(defaultConfigPath)
	if len(args) > 0 {
		return console.runCommand(args)
	}
	return console.runMenu()
}

type managementConsole struct {
	in         *bufio.Reader
	out        io.Writer
	errOut     io.Writer
	manager    string
	configPath string
	config     Config
}

func (c *managementConsole) runMenu() int {
	for {
		c.clearScreen()
		c.printHeader()
		fmt.Fprintln(c.out, "1. 查看运行状态")
		fmt.Fprintln(c.out, "2. 启动 Agent 和内核")
		fmt.Fprintln(c.out, "3. 停止 Agent 和内核")
		fmt.Fprintln(c.out, "4. 重启 Agent 和内核")
		fmt.Fprintln(c.out, "5. 查看 Agent 日志")
		fmt.Fprintln(c.out, "6. 查看 oboard-sb 日志")
		fmt.Fprintln(c.out, "7. 检查与主控的连接")
		fmt.Fprintln(c.out, "0. 退出")
		fmt.Fprint(c.out, "\n请选择操作：")
		choice, err := c.in.ReadString('\n')
		if err != nil && strings.TrimSpace(choice) == "" {
			return 0
		}
		fmt.Fprintln(c.out)
		switch strings.TrimSpace(choice) {
		case "1":
			c.printStatus()
		case "2":
			c.serviceAction("start")
		case "3":
			c.serviceAction("stop")
		case "4":
			c.serviceAction("restart")
		case "5":
			c.printLogs(c.agentService())
		case "6":
			c.printLogs(c.coreService())
		case "7":
			c.printControllerCheck()
		case "0", "q", "quit", "exit":
			fmt.Fprintln(c.out, "已退出 OBoard Agent 管理。")
			return 0
		default:
			fmt.Fprintln(c.out, "无法识别该选项，请输入菜单中的数字。")
		}
		c.waitForEnter()
	}
}

func (c *managementConsole) runCommand(args []string) int {
	switch strings.ToLower(strings.TrimSpace(args[0])) {
	case "status":
		c.printHeader()
		c.printStatus()
	case "start", "stop", "restart":
		c.serviceAction(strings.ToLower(args[0]))
	case "logs", "log":
		service := c.agentService()
		if len(args) > 1 && (args[1] == "core" || args[1] == "sb" || args[1] == "oboard-sb") {
			service = c.coreService()
		}
		c.printLogs(service)
	case "check", "connection", "controller":
		c.printControllerCheck()
	case "help", "-h", "--help":
		c.printHelp()
	default:
		fmt.Fprintf(c.errOut, "未知命令：%s\n", args[0])
		c.printHelp()
		return 2
	}
	return 0
}

func (c *managementConsole) printHeader() {
	fmt.Fprintln(c.out, "OBoard Agent 管理")
	fmt.Fprintln(c.out, "=================")
	fmt.Fprintf(c.out, "服务管理：%s\n", friendlyManager(c.manager))
	if c.configPath != "" {
		fmt.Fprintf(c.out, "主控地址：%s\n", displayControllerURL(c.config.ControllerURL))
	} else {
		fmt.Fprintln(c.out, "主控地址：尚未找到 Agent 配置")
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(c.out, "提示：查看功能可以使用；启动、停止和重启需要 root 权限。")
	}
	fmt.Fprintln(c.out)
}

func (c *managementConsole) printHelp() {
	fmt.Fprintln(c.out, "用法：")
	fmt.Fprintln(c.out, "  obag                 打开管理菜单")
	fmt.Fprintln(c.out, "  obag status          查看运行状态")
	fmt.Fprintln(c.out, "  obag start           启动 Agent 和内核")
	fmt.Fprintln(c.out, "  obag stop            停止 Agent 和内核")
	fmt.Fprintln(c.out, "  obag restart         重启 Agent 和内核")
	fmt.Fprintln(c.out, "  obag logs agent      查看 Agent 日志")
	fmt.Fprintln(c.out, "  obag logs core       查看 oboard-sb 日志")
	fmt.Fprintln(c.out, "  obag check           检查与主控的连接")
}

func (c *managementConsole) printStatus() {
	if c.manager == "" {
		fmt.Fprintln(c.out, "未找到 systemd 或 OpenRC，无法读取服务状态。")
		return
	}
	fmt.Fprintf(c.out, "Agent：%s\n", c.serviceStatus(c.agentService()))
	fmt.Fprintf(c.out, "内核：%s\n", c.serviceStatus(c.coreService()))
}

func (c *managementConsole) serviceAction(action string) {
	if os.Geteuid() != 0 {
		fmt.Fprintln(c.out, "该操作需要 root 权限，请使用 sudo obag 或切换到 root 后重试。")
		return
	}
	if c.manager == "" {
		fmt.Fprintln(c.out, "未找到支持的服务管理器。当前支持 systemd 和 OpenRC。")
		return
	}
	services := []string{c.coreService(), c.agentService()}
	if action == "stop" {
		services = []string{c.agentService(), c.coreService()}
	}
	labels := map[string]string{"start": "启动", "stop": "停止", "restart": "重启"}
	for _, service := range services {
		fmt.Fprintf(c.out, "%s %s... ", labels[action], service)
		var output string
		var err error
		if c.manager == "systemd" {
			output, err = commandOutput(20*time.Second, "systemctl", action, service)
		} else {
			output, err = commandOutput(20*time.Second, "rc-service", service, action)
		}
		if err != nil {
			fmt.Fprintln(c.out, "失败")
			if text := strings.TrimSpace(scrubDiagnosticOutput(output)); text != "" {
				fmt.Fprintln(c.out, text)
			} else {
				fmt.Fprintln(c.out, friendlyCommandError(err))
			}
			continue
		}
		fmt.Fprintln(c.out, "完成")
	}
}

func (c *managementConsole) serviceStatus(service string) string {
	var output string
	var err error
	if c.manager == "systemd" {
		output, err = commandOutput(5*time.Second, "systemctl", "is-active", service)
	} else {
		output, err = commandOutput(5*time.Second, "rc-service", service, "status")
	}
	text := strings.ToLower(strings.TrimSpace(output))
	if err == nil && (text == "active" || strings.Contains(text, "started")) {
		return "运行中"
	}
	if strings.Contains(text, "inactive") || strings.Contains(text, "stopped") || strings.Contains(text, "crashed") {
		return "已停止"
	}
	if text != "" {
		return strings.TrimSpace(scrubDiagnosticOutput(output))
	}
	return "状态未知"
}

func (c *managementConsole) printLogs(service string) {
	fmt.Fprintf(c.out, "最近 %d 行 %s 日志\n", managementLogLines, service)
	fmt.Fprintln(c.out, "----------------------------------------")
	var output string
	var err error
	if c.manager == "systemd" {
		if _, lookupErr := exec.LookPath("journalctl"); lookupErr == nil {
			output, err = commandOutput(15*time.Second, "journalctl", "-u", service, "-n", fmt.Sprint(managementLogLines), "--no-pager")
		} else {
			output, err = c.logFileContent(service)
		}
	} else {
		output, err = c.logFileContent(service)
	}
	output = strings.TrimSpace(scrubDiagnosticOutput(output))
	if output != "" {
		fmt.Fprintln(c.out, output)
	}
	if err != nil && output == "" {
		fmt.Fprintln(c.out, "暂时没有可读取的日志。")
		fmt.Fprintln(c.out, friendlyCommandError(err))
	}
}

func (c *managementConsole) logFileContent(service string) (string, error) {
	path := filepath.Join("/var/log", service+".log")
	item := readDiagnosticTail(path, managementLogLines)
	if ok, _ := item["ok"].(bool); ok {
		content, _ := item["content"].(string)
		return content, nil
	}
	fallback := readOpenRCSystemLogFallback(service, managementLogLines)
	if ok, _ := fallback["ok"].(bool); ok {
		content, _ := fallback["content"].(string)
		return content, nil
	}
	return "", fmt.Errorf("未找到 %s 的日志文件", service)
}

func (c *managementConsole) printControllerCheck() {
	fmt.Fprintln(c.out, "检查与主控的连接")
	fmt.Fprintln(c.out, "------------------")
	result := checkManagementController(c.config)
	for _, item := range result.Items {
		mark := "[成功]"
		if !item.OK {
			mark = "[失败]"
		}
		fmt.Fprintf(c.out, "%s %s：%s\n", mark, item.Name, item.Message)
	}
	if result.OK {
		fmt.Fprintln(c.out, "\nAgent 所在服务器可以正常访问主控。")
	} else {
		fmt.Fprintln(c.out, "\n连接检查未全部通过，请根据上面的失败项目检查网络、域名或主控服务。")
	}
}

type managementCheckItem struct {
	Name    string
	OK      bool
	Message string
}

type managementCheckResult struct {
	OK    bool
	Items []managementCheckItem
}

func checkManagementController(cfg Config) managementCheckResult {
	result := managementCheckResult{OK: true}
	raw := strings.TrimSpace(cfg.ControllerURL)
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return managementCheckResult{Items: []managementCheckItem{{Name: "主控地址", Message: "Agent 配置中没有有效的主控地址"}}}
	}
	result.Items = append(result.Items, managementCheckItem{Name: "主控地址", OK: true, Message: displayControllerURL(raw)})

	dnsCtx, cancelDNS := context.WithTimeout(context.Background(), 5*time.Second)
	addresses, dnsErr := net.DefaultResolver.LookupHost(dnsCtx, u.Hostname())
	cancelDNS()
	if dnsErr != nil {
		result.OK = false
		result.Items = append(result.Items, managementCheckItem{Name: "域名解析", Message: friendlyCommandError(dnsErr)})
	} else {
		result.Items = append(result.Items, managementCheckItem{Name: "域名解析", OK: true, Message: strings.Join(addresses, ", ")})
	}

	port := u.Port()
	if port == "" {
		if u.Scheme == "https" || u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	conn, tcpErr := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 5*time.Second)
	if tcpErr != nil {
		result.OK = false
		result.Items = append(result.Items, managementCheckItem{Name: "网络连接", Message: friendlyCommandError(tcpErr)})
	} else {
		_ = conn.Close()
		result.Items = append(result.Items, managementCheckItem{Name: "网络连接", OK: true, Message: "已连接到 " + net.JoinHostPort(u.Hostname(), port)})
	}

	healthURL := *u
	if healthURL.Scheme == "ws" {
		healthURL.Scheme = "http"
	} else if healthURL.Scheme == "wss" {
		healthURL.Scheme = "https"
	}
	healthURL.Path = "/healthz"
	healthURL.RawQuery = ""
	healthURL.Fragment = ""
	httpCtx, cancelHTTP := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelHTTP()
	req, reqErr := http.NewRequestWithContext(httpCtx, http.MethodGet, healthURL.String(), nil)
	if reqErr != nil {
		result.OK = false
		result.Items = append(result.Items, managementCheckItem{Name: "主控服务", Message: friendlyCommandError(reqErr)})
		return result
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, httpErr := client.Do(req)
	if httpErr != nil {
		result.OK = false
		result.Items = append(result.Items, managementCheckItem{Name: "主控服务", Message: friendlyCommandError(httpErr)})
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			result.Items = append(result.Items, managementCheckItem{Name: "主控服务", OK: true, Message: "健康检查正常"})
		} else {
			result.OK = false
			result.Items = append(result.Items, managementCheckItem{Name: "主控服务", Message: "主控返回 " + resp.Status})
		}
	}
	return result
}

func loadManagementConfig(defaultPath string) (string, Config) {
	candidates := []string{strings.TrimSpace(os.Getenv("OBOARD_AGENT_CONFIG")), "/etc/oboard-agent/config.json", defaultPath, "/root/.oboard-agent/config.json"}
	seen := map[string]bool{}
	for _, path := range candidates {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		cfg, err := LoadConfig(path)
		if err == nil {
			cfg.ConfigPath = path
			return path, normalizeConfig(cfg)
		}
	}
	return "", normalizeConfig(Config{})
}

func (c *managementConsole) agentService() string { return managementAgentService }

func (c *managementConsole) coreService() string {
	if service := strings.TrimSpace(c.config.CoreService); service != "" {
		return service
	}
	return managementCoreService
}

func (c *managementConsole) waitForEnter() {
	fmt.Fprint(c.out, "\n按 Enter 返回菜单...")
	_, _ = c.in.ReadString('\n')
}

func (c *managementConsole) clearScreen() {
	if strings.TrimSpace(os.Getenv("TERM")) != "" && os.Getenv("TERM") != "dumb" {
		fmt.Fprint(c.out, "\033[2J\033[H")
	}
}

func friendlyManager(manager string) string {
	switch manager {
	case "systemd":
		return "systemd"
	case "openrc":
		return "OpenRC"
	default:
		return "未识别"
	}
}

func displayControllerURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "未配置"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func friendlyCommandError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	text = strings.ReplaceAll(text, "context deadline exceeded", "连接超时")
	text = strings.ReplaceAll(text, "connection refused", "连接被拒绝")
	text = strings.ReplaceAll(text, "no such host", "无法解析主机")
	return text
}
