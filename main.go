package main

import (
	"cockcrow/auxiliary"
	"cockcrow/collect"
	"cockcrow/directory"
	"cockcrow/exploit"
	"cockcrow/explosion"
	"cockcrow/finger"
	"cockcrow/fishing"
	"cockcrow/mapping"
	"cockcrow/proxy"
	"cockcrow/scan"
	"cockcrow/subdomain"
	"fmt"
	"github.com/peterh/liner"
	"math/rand"
	"os"
	"strings"
	"time"
)

type CommandHandler func(args []string)

type CLI struct {
	prompt          string
	commandHandlers map[string]CommandHandler
	module          string
	history         []string
	allowedModules  []string
}

func NewCLI(prompt string) CLI {
	return CLI{
		prompt:          prompt,
		commandHandlers: make(map[string]CommandHandler),
		module:          "",
		history:         []string{},
		allowedModules:  []string{"scan", "exploit", "collect", "mapping", "subdomain", "directory", "finger", "explosion", "proxy", "auxiliary", "fishing"},
	}
}

func (cli *CLI) RegisterCommand(command string, handler CommandHandler) {
	cli.commandHandlers[command] = handler
}

func (cli *CLI) Start() {
	line := liner.NewLiner()
	defer line.Close()

	line.SetCtrlCAborts(true)

	line.ReadHistory(strings.NewReader(strings.Join(cli.history, "\n")))

	line.SetCompleter(func(input string) (completions []string) {
		parts := strings.SplitN(input, " ", 2)
		command := parts[0]

		if command == "use" && cli.module == "" && len(parts) > 1 {
			for _, module := range cli.allowedModules {
				if strings.HasPrefix(module, parts[1]) {
					completions = append(completions, "use "+module)
				}
			}
			return
		}

		if cli.module == "scan" && command == "set" {
			options := []string{"target", "targets", "port_range", "scan_speed", "no_ping"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "subdomain" && command == "set" {
			options := []string{"domain", "level", "dict"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "explosion" && command == "set" {
			options := []string{"target", "port", "targets", "user_dict", "pass_dict", "server_type"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "directory" && command == "set" {
			options := []string{"target", "targets", "type", "level", "dict"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "proxy" && command == "set" {
			options := []string{"target", "port", "type", "user", "pass"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "finger" && command == "set" {
			options := []string{"target", "targets", "type"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "collect" && command == "set" {
			options := []string{"company"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "mapping" && command == "set" {
			options := []string{"company", "domain"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "exploit" && command == "set" {
			options := []string{"target", "targets", "type"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "auxiliary" && command == "set" {
			options := []string{"attack_ip"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}
		if cli.module == "fishing" && command == "set" {
			options := []string{"text", "target", "targets", "annex"}
			for _, option := range options {
				if len(parts) > 1 && strings.HasPrefix(option, parts[1]) {
					completions = append(completions, "set "+option)
				}
			}
			return
		}

		for cmd := range cli.commandHandlers {
			if strings.HasPrefix(cmd, input) {
				completions = append(completions, cmd)
			}
		}
		return
	})

	cli.printWelcomeMessage()

	for {
		// 动态生成提示符
		prompt := cli.prompt
		if cli.module != "" {
			prompt = fmt.Sprintf("%s [%s]> ", strings.TrimSuffix(cli.prompt, ">"), cli.module)
		}

		input, err := line.Prompt(prompt)
		if err != nil {
			if err == liner.ErrPromptAborted {
				fmt.Println("\nUse 'exit' to leave the cli.")
				continue
			}
			fmt.Println("Error reading input:", err)
			break
		}

		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}

		line.AppendHistory(input)
		cli.history = append(cli.history, input)

		args := strings.Split(input, " ")
		command := args[0]

		handler, exists := cli.commandHandlers[command]
		if !exists {
			fmt.Printf("Unknown command: %s\n", command)
			continue
		}

		handler(args[1:])
	}

	file, _ := os.Create(".history")
	defer file.Close()
	line.WriteHistory(file)
}

// 定义支持的 ANSI 颜色代码
var colors = []string{
	"\033[31m",   // 红色
	"\033[32m",   // 绿色
	"\033[33m",   // 黄色
	"\033[34m",   // 蓝色
	"\033[35m",   // 紫色
	"\033[36m",   // 青色
	"\033[37m",   // 白色
	"\033[90m",   // 灰色
	"\033[91m",   // 浅红色
	"\033[92m",   // 浅绿色
	"\033[93m",   // 浅黄色
	"\033[94m",   // 浅蓝色
	"\033[95m",   // 浅紫色
	"\033[96m",   // 浅青色
	"\033[97m",   // 亮白色
	"\033[1;31m", // 加粗红色
	"\033[1;32m", // 加粗绿色
	"\033[1;33m", // 加粗黄色
	"\033[1;34m", // 加粗蓝色
	"\033[1;35m", // 加粗紫色
	"\033[1;36m", // 加粗青色
	"\033[1;37m", // 加粗白色
}

// 随机选择一种颜色
func randomColor() string {
	rand.Seed(time.Now().UnixNano())
	return colors[rand.Intn(len(colors))]
}

// 分割字符串为行
func splitLines(s string) []string {
	return strings.Split(s, "\n")
}
func (cli *CLI) printWelcomeMessage() {
	ico := `
Welcome to cockcrow! Type 'help' for a list of commands.   

      _________  _____/ /___________ _      __
     / ___/ __ \/ ___/ //_/ ___/ __ | | /| / /
    / /__/ /_/ / /__/ ,< / /  / /_/ | |/ |/ / 
    \___/\____/\___/_/|_/_/   \____/|__/|__/  

` + `[+]version: 0.0.1              [+]by A_llen` + `
`
	lines := splitLines(ico)

	for _, line := range lines {
		fmt.Printf("%s%s\033[0m\n", randomColor(), line)
	}

}

func (cli *CLI) isValidModule(module string) bool {
	for _, m := range cli.allowedModules {
		if m == module {
			return true
		}
	}
	return false
}

func main() {
	cli := NewCLI("cockcrow >")

	cli.RegisterCommand("help", func(args []string) {
		fmt.Println("Available commands:")
		fmt.Println("  help       - Show this help message")
		fmt.Println("  exit       - Exit the cli")
		fmt.Println("  use        - Select a module")
		fmt.Println("  scan       - Perform a network scan")
		fmt.Println("  explosion  - Conduct password explosion for specific services")
		fmt.Println("  exploit    - Exploit vulnerabilities")
		fmt.Println("  collect    - Collect company names")
		fmt.Println("  mapping    - Spatial surveying and mapping")
		fmt.Println("  subdomain  - Subdomain explosion")
		fmt.Println("  directory  - Website directory explosion")
		fmt.Println("  finger     - Fingerprint identification")
		fmt.Println("  auxiliary  - Auxiliary module")
		fmt.Println("  fishing    - Fishing module")
		fmt.Println("  proxy      - Global proxy module")
		fmt.Println("  options    - View configuration content")
		fmt.Println("  set        - Set configuration content")
		fmt.Println("  run        - Execute a module")
		fmt.Println("  return     - Return to the main menu")
	})

	cli.RegisterCommand("exit", func(args []string) {
		fmt.Println("Exiting...")
		os.Exit(0)
	})

	cli.RegisterCommand("use", func(args []string) {
		if cli.module != "" {
			fmt.Println("Cannot select a new module while in another module. Use 'return' first.")
			return
		}
		if len(args) < 1 {
			fmt.Println("Usage: use <module>")
			return
		}
		module := args[0]
		if !cli.isValidModule(module) {
			fmt.Printf("Invalid module: '%s'. Allowed modules: %v\n", module, cli.allowedModules)
			return
		}
		cli.module = module
		fmt.Printf("Module '%s' selected. Type 'return' to go back to the main menu.\n", module)
	})

	cli.RegisterCommand("return", func(args []string) {
		if cli.module == "" {
			fmt.Println("No module selected. You are already in the main menu.")
			return
		}
		fmt.Printf("Exiting module '%s' and returning to the main menu.\n", cli.module)
		cli.module = ""
	})

	cli.RegisterCommand("options", func(args []string) {
		if cli.module == "" {
			fmt.Println("No module selected. Use 'use <module>' to select a module.")
			return
		}
		switch cli.module {
		case "scan":
			fmt.Println("Options for 'scan':")
			fmt.Println("  target      - eg: set ip 192.168.1.1 or 192.168.1.1/24 or www.baidu.com")
			fmt.Println("  targets     - eg: set ip_file ./ip.txt")
			fmt.Println("  port_range  - eg: set port_range 1-65535")
			fmt.Println("  scan_speed  - eg: set scan_speed 0 or 1｜2｜3｜4｜5")
			fmt.Println("  no_ping     - eg: set no_ping true")
		case "subdomain":
			fmt.Println("Options for 'subdomain':")
			fmt.Println("  domain      - eg: set domain baidu.com")
			fmt.Println("  level       - eg: set level 2")
			fmt.Println("  dict        - eg: set dict ./subdomain_dict1.txt")
		case "directory":
			fmt.Println("Options for 'directory':")
			fmt.Println("  target      - eg: set target https://www.baidu.com")
			fmt.Println("  targets     - eg: set targets ./uri.txt")
			fmt.Println("  type        - eg: set type jsp｜jspx｜asp｜aspx｜php｜mdb｜dir｜backup")
			fmt.Println("  level       - eg: set level 2")
			fmt.Println("  dict        - eg: set dict ./directory_php_dict.txt")
		case "finger":
			fmt.Println("Options for 'finger':")
			fmt.Println("  target      - eg: set target https://www.baidu.com")
			fmt.Println("  targets     - eg: set targest uri.txt")
			fmt.Println("  type        - eg: set targest md5｜header")
		case "explosion":
			fmt.Println("Options for 'explosion':")
			fmt.Println("  target      - eg: set target 192.168.1.1")
			fmt.Println("  port        - eg: set port 22")
			fmt.Println("  targets     - eg: set targets ./targets.txt")
			fmt.Println("  user_dict   - eg: set user_dict ./username_dict.txt")
			fmt.Println("  pass_dict   - eg: set pass_dict ./password_dict.txt")
			fmt.Println("  server_type - eg: set server_type ssh｜ftp｜rdp｜redis｜mysql｜mssql｜oracle｜telnet｜mongodb｜postgresql｜memcached")
		case "mapping":
			fmt.Println("Options for 'mapping':")
			fmt.Println("  company       - eg: set company 北京市xxx科技发展有限公司")
			fmt.Println("  domain        - eg: set domain xxx.com")

		case "collect":
			fmt.Println("Options for 'collect':")
			fmt.Println("  company       	- eg: set company 北京市xxx科技发展有限公司")

		case "exploit":
			fmt.Println("Options for 'exploit':")
			fmt.Println("  target      - eg: set target https://192.168.1.1/")
			fmt.Println("  targets     - eg: set targets uri.txt")
			fmt.Println("  type        - eg: set type xxx")
		case "proxy":
			fmt.Println("Options for 'proxy':")
			fmt.Println("  target    - eg: set target 192.168.1.1")
			fmt.Println("  port      - eg: set port 1080")
			fmt.Println("  type      - eg: set socks5、http ")
			fmt.Println("  user      - eg: set user admin")
			fmt.Println("  pass      - eg: set pass admin")
		case "fishing":
			fmt.Println("Options for 'proxy':")
			fmt.Println("  target    - eg: set target hr@xxx.com")
			fmt.Println("  targets   - eg: set targets email_targets.txt")
			fmt.Println("  text      - eg: set text email_config.txt ")
			fmt.Println("  annex      - eg: set annex ./c2.exe")

		case "auxiliary":
			fmt.Println("Options for 'auxiliary':")
			fmt.Println("  attack_ip      - eg: set attack_ip 192.168.1.1")

		default:
			fmt.Println("Options are not implemented for this module.")
		}
	})

	cli.RegisterCommand("set", func(args []string) {
		if cli.module == "" {
			fmt.Println("No module selected. Use 'use <module>' to select a module.")
			return
		}
		if len(args) < 2 {
			fmt.Println("Usage: set <option> <value>")
			return
		}
		option := args[0]
		value := strings.Join(args[1:], " ")
		var err error

		switch cli.module {
		case "scan":
			err = scan.SetOption(option, value)
		case "subdomain":
			err = subdomain.SetOption(option, value)
		case "explosion":
			err = explosion.SetOption(option, value)
		case "directory":
			err = directory.SetOption(option, value)
		case "proxy":
			err = proxy.SetOption(option, value)
		case "finger":
			err = finger.SetOption(option, value)
		case "collect":
			err = collect.SetOption(option, value)
		case "mapping":
			err = mapping.SetOption(option, value)
		case "exploit":
			err = exploit.SetOption(option, value)
		case "auxiliary":
			err = auxiliary.SetOption(option, value)
		case "fishing":
			err = fishing.SetOption(option, value)

		default:
			fmt.Println("The 'set' command is not implemented for the current module.")
			return
		}

		if err != nil {
			fmt.Println("Error setting option:", err)
			return
		}
		fmt.Printf("Option '%s' set to '%s'\n", option, value)
	})

	cli.RegisterCommand("run", func(args []string) {
		switch cli.module {
		case "scan":
			if err := scan.Execute(); err != nil {
				fmt.Println("Error executing scan:", err)
			}
		case "subdomain":
			if err := subdomain.Execute(); err != nil {
				fmt.Println("Error executing subdomain scan:", err)
			}
		case "explosion":
			if err := explosion.Execute(); err != nil {
				fmt.Println("Error executing explosion scan:", err)
			}
		case "directory":
			if err := directory.Execute(); err != nil {
				fmt.Println("Error executing directory scan:", err)
			}
		case "proxy":
			if err := proxy.Execute(); err != nil {
				fmt.Println("Global proxy module failed to start:", err)
			}
		case "finger":
			if err := finger.Execute(); err != nil {
				fmt.Println("Website fingerprint recognition module failed to start:", err)
			}
		case "collect":
			if err := collect.Execute(); err != nil {
				fmt.Println("Collect company information module failed to start:", err)
			}
		case "mapping":
			if err := mapping.Execute(); err != nil {
				fmt.Println("Asset mapping module failed to start:", err)
			}
		case "exploit":
			if err := exploit.Execute(); err != nil {
				fmt.Println("Exploiting vulnerabilities module failed to start:", err)
			}
		case "auxiliary":
			if err := auxiliary.Execute(); err != nil {
				fmt.Println("Auxiliary module failed to start:", err)
			}
		case "fishing":
			if err := fishing.Execute(); err != nil {
				fmt.Println("Fishing module failed to start:", err)
			}
		default:
			fmt.Println("Run is not implemented for the selected module.")
		}
	})

	cli.Start()
}
