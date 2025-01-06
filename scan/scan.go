package scan

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3" // 引入进度条库
)

type ScanConfig struct {
	IP        string
	IPFile    string
	PortRange string
	ScanSpeed time.Duration
	NoPing    bool
}

var config ScanConfig

// 设置选项
func SetOption(option, value string) error {
	switch option {
	case "target":
		config.IP = value
		config.IPFile = ""
	case "targets":
		config.IPFile = value
		config.IP = ""
	case "port_range":
		config.PortRange = value
	case "scan_speed":
		speed, err := strconv.Atoi(value)
		if err != nil {
			return fmt.Errorf("invalid scan speed: %v", err)
		}
		config.ScanSpeed = time.Duration(speed) * time.Millisecond
	case "no_ping":
		noPing, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid no_ping value: %v", err)
		}
		config.NoPing = noPing
		if !config.NoPing {
			return fmt.Errorf("noping option is currently only supported when true")
		}
	default:
		return fmt.Errorf("unknown option: %s", option)
	}
	return nil
}

// 列出当前配置
func Table() {
	fmt.Println("Current Configuration:")
	fmt.Printf("IP: %s\n", config.IP)
	fmt.Printf("IP File: %s\n", config.IPFile)
	fmt.Printf("Port Range: %s\n", config.PortRange)
	fmt.Printf("Scan Speed: %v\n", config.ScanSpeed)
	fmt.Printf("No Ping: %t\n", config.NoPing)
}

// 主执行逻辑
func Execute() error {
	if config.IP == "" && config.IPFile == "" {
		return fmt.Errorf("either IP address or IP file must be set")
	}

	var hosts []string
	if config.IPFile != "" {
		ips, err := readIPsFromFile(config.IPFile)
		if err != nil {
			return err
		}
		hosts = ips
	} else if strings.Contains(config.IP, "/") {
		hosts = cidrToHosts(config.IP)
	} else {
		hosts = []string{config.IP}
	}

	fmt.Println("Performing host discovery...")
	liveHosts := discoverHosts(hosts)

	fmt.Printf("Discovered %d live hosts:\n", len(liveHosts))
	for _, host := range liveHosts {
		fmt.Println(host)
	}

	if len(liveHosts) > 0 {
		var wg sync.WaitGroup
		for _, host := range liveHosts {
			wg.Add(1)
			go func(host string) {
				defer wg.Done()
				fmt.Printf("\nScanning ports for host: %s\n", host)
				openPorts := performScan(host, config.PortRange, config.ScanSpeed)
				for _, port := range openPorts {
					service := identifyService(host, port)
					//fmt.Printf("Detected service on port %d: %s\n", port, service)
					if service == "Unknown" {
						checkUnknownPort(host, port)
					}
				}
			}(host)
		}
		wg.Wait()
	} else {
		fmt.Println("No live hosts found.")
	}
	return nil
}

// 主机发现
func discoverHosts(hosts []string) []string {
	var liveHosts []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, host := range hosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			if config.NoPing || isHostAlive(host) {
				mu.Lock()
				liveHosts = append(liveHosts, host)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return liveHosts
}

// 端口扫描
func performScan(host, portRange string, scanSpeed time.Duration) []int {
	startPort, endPort, err := parsePortRange(portRange)
	if err != nil {
		fmt.Printf("Invalid port range: %s\n", portRange)
		return nil
	}

	var openPorts []int
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 初始化线程安全的进度条
	bar := progressbar.NewOptions(endPort-startPort+1,
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionClearOnFinish(),
	)

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			address := fmt.Sprintf("%s:%d", host, port)
			conn, err := net.DialTimeout("tcp", address, scanSpeed)
			if err == nil {
				mu.Lock()
				openPorts = append(openPorts, port)
				mu.Unlock()
				_ = conn.Close()
			}

			// 线程安全更新进度条
			mu.Lock()
			_ = bar.Add(1)
			mu.Unlock()
		}(port)
	}

	wg.Wait()

	// 高亮显示扫描到的开放端口，直接附带服务类型
	if len(openPorts) > 0 {
		fmt.Printf("\n\033[32m[+] Open ports on %s\033[0m\n", host)
		for _, port := range openPorts {
			service := identifyService(host, port)
			fmt.Printf("\n\033[32m  - Port %d is open \u001B[1;35m[%s]\033[0m\n", port, service)
		}
	} else {
		fmt.Printf("\n\033[33m[-] No open ports found on %s.\033[0m\n", host)
	}

	return openPorts
}

// 检查未知端口服务
func checkUnknownPort(host string, port int) {
	protocols := []string{"http", "https"}
	for _, protocol := range protocols {
		url := fmt.Sprintf("%s://%s:%d", protocol, host, port)
		resp, err := http.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		title := extractTitle(resp)
		if title != "" {
			fmt.Printf("\n[+] Title found on %s: %s\n", url, title)
		} else {
			fmt.Printf("\n[-] No title found on %s\n", url)
		}
	}
}

// 提取标题信息
func extractTitle(resp *http.Response) string {
	var title string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "<title>") {
			titleStart := strings.Index(line, "<title>") + 7
			titleEnd := strings.Index(line, "</title>")
			if titleEnd > titleStart {
				title = line[titleStart:titleEnd]
			}
			break
		}
	}
	return title
}

// 检查主机是否存活
func isHostAlive(host string) bool {
	// 优先使用 TCP 探测常见端口，如 80, 443, 22 等
	commonPorts := []int{80, 443, 22}
	for _, port := range commonPorts {
		address := fmt.Sprintf("%s:%d", host, port)
		conn, err := net.DialTimeout("tcp", address, 1*time.Second)
		if err == nil {
			_ = conn.Close()
			return true
		}
	}

	// 如果 TCP 检测失败，尝试使用 ping 命令（需要系统支持）
	pingCmd := "ping"
	pingArgs := []string{"-c", "1", "-W", "1", host} // Linux/macOS 参数
	if isWindows() {
		pingCmd = "ping"
		pingArgs = []string{"-n", "1", "-w", "1000", host} // Windows 参数
	}

	cmd := exec.Command(pingCmd, pingArgs...)
	output, err := cmd.CombinedOutput()
	if err == nil && strings.Contains(string(output), "1 received") {
		return true
	}

	return false
}

// 检查是否为 Windows 系统
func isWindows() bool {
	return strings.Contains(strings.ToLower(runtime.GOOS), "windows")
}

// CIDR 转换为主机列表
func cidrToHosts(cidr string) []string {
	var hosts []string
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Printf("Invalid CIDR: %v\n", err)
		return hosts
	}
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		hosts = append(hosts, ip.String())
	}
	return hosts[1 : len(hosts)-1]
}

// 递增 IP 地址
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// 从文件读取 IP 地址
func readIPsFromFile(filePath string) ([]string, error) {
	var ips []string
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("Failed to open file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		ips = append(ips, strings.TrimSpace(scanner.Text()))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("Error reading file: %v", err)
	}
	return ips, nil
}

// 解析端口范围
func parsePortRange(portRange string) (int, int, error) {
	parts := strings.Split(portRange, "-")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("Invalid port range format")
	}
	startPort, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("Invalid start port: %v", err)
	}
	endPort, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("Invalid end port: %v", err)
	}
	if startPort > endPort {
		return 0, 0, fmt.Errorf("Start port must be less than or equal to end port")
	}
	return startPort, endPort, nil
}

// 识别服务类型
func identifyService(host string, port int) string {
	// 先根据端口号进行初步服务识别
	switch port {
	case 21:
		return "FTP" // FTP 默认端口
	case 22:
		return "SSH" // SSH 默认端口
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 81:
		return "IPCam"
	case 110:
		return "POP3"
	case 139:
		return "Samba"
	case 389:
		return "LDAP"
	case 445:
		return "SMB"
	case 873:
		return "Rsync"
	case 1080:
		return "Socks5"
	case 1352:
		return "Lotus Domino"
	case 1433:
		return "MsSQL"
	case 1521:
		return "Oracle"
	case 2049:
		return "NFS"
	case 2181:
		return "ZooKeeper"
	case 2375:
		return "Docker Remote API"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 4440:
		return "Rundeck"
	case 4848:
		return "GlassFish"
	case 5000:
		return "Sybase/DB2"
	case 5432:
		return "PostgreSQL"
	case 5632:
		return "pcAnywhere"
	case 5900:
		return "VNC"
	case 6082:
		return "Varnish"
	case 6379:
		return "Redis"
	case 8000:
		return "JBoss"
	case 8009:
		return "Tomcat-AJP"
	case 8080:
		return "Tomcat"
	case 8082:
		return "H2"
	case 8089:
		return "Resin"
	case 8649:
		return "Ganglia"
	case 9000:
		return "FastCGI"
	case 9090:
		return "WebSphere"
	case 11211:
		return "mecached"
	case 50000:
		return "SAP"
	case 67, 68:
		return "DHCP"
	case 80, 443:
		return "HTTP/HTTPS" // HTTP/HTTPS 默认端口
	case 161, 162:
		return "SNMP"
	case 512, 513, 514:
		return "linux Rexec"
	case 2601, 2604:
		return "Zebra"
	case 3128, 3312:
		return "Squid"
	case 7001, 7002:
		return "WebLogic"
	case 8083, 8086:
		return "influxDB"
	case 9200, 9300:
		return "Elasticsearch"
	case 8069, 10050:
		return "Zabbix"
	case 61616, 8161:
		return "ActiveMQ"
	case 27017, 27018, 28017:
		return "MongoDB"
	case 8088, 50060, 50070:
		return "Hadoop"
	default:
		// 如果端口不是常见端口，则根据Banner进行进一步识别
		return "Unknown"
	}
}

// 根据Banner识别服务类型
func identifyByBanner(host string, port int) string {
	address := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", address, 2*time.Second) // 延长连接超时
	if err != nil {
		return "timeout"
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second)) // 延长读取超时
	resp := make([]byte, 8192)                            // 增大缓冲区
	n, err := conn.Read(resp)
	if err != nil {
		return identifyService(host, port)
	}

	// 判断返回的Banner，根据Banner内容识别服务
	switch {
	case strings.Contains(string(resp[:n]), "SSH-") || port == 22:
		return "SSH"
	case strings.Contains(string(resp[:n]), "Pure-FTPd") || strings.Contains(string(resp[:n]), "220 FTP") || strings.Contains(string(resp[:n]), "FTP") || strings.Contains(string(resp[:n]), "vsFTPd") || strings.Contains(string(resp[:n]), "ProFTPD") || strings.Contains(string(resp[:n]), "220 Service ready for new user"):
		return "FTP"
	case strings.Contains(string(resp[:n]), "MySQL Protocol:") || strings.Contains(string(resp[:n]), "-log") || strings.Contains(string(resp[:n]), "mysql_native_password") || port == 3306:
		return "MySQL"
	case strings.Contains(string(resp[:n]), "E\\x00\\x00\\x00") || strings.Contains(string(resp[:n]), "postgresql"):
		return "PostgreSQL"
	case strings.Contains(string(resp[:n]), "-ERR wrong number") || strings.Contains(string(resp[:n]), "-NOAUTH Authentication required.") || port == 6379:
		return "Redis"
	case strings.Contains(string(resp[:n]), "\\x03\\x00\\x00") || strings.Contains(string(resp[:n]), "Selected Protocols:") || strings.Contains(string(resp[:n]), "OS Build") || strings.Contains(string(resp[:n]), "Windows"):
		return "RDP"
	case strings.Contains(string(resp[:n]), "HTTP/"):
		return "HTTP/HTTPS"
	case strings.Contains(string(resp[:n]), "NTLMSSP") || strings.Contains(string(resp[:n]), "ServerDefaultDialect: SMB 3.0"):
		return "SMB"
	case strings.Contains(string(resp[:n]), "VNC") || strings.Contains(string(resp[:n]), "RFB"):
		return "VNC"
	case strings.Contains(string(resp[:n]), "MongoDB") || strings.Contains(string(resp[:n]), "!\\x07version\\x04bind7 t{RPowerDNS Recursor 410"):
		return "MongoDB"
	case strings.Contains(string(resp[:n]), "AMQP") || strings.Contains(string(resp[:n]), "product: RabbitMQ"):
		return "RabbitMQ"
	case strings.Contains(string(resp[:n]), "cluster_name") || strings.Contains(string(resp[:n]), "This is not a HTTP port"):
		return "Elasticsearch"
	case strings.Contains(string(resp[:n]), "Cassandra") || strings.Contains(string(resp[:n]), "\\x85\\x10\\x00\\x00\\x00\\x00\\x00\\x00b\\x00\\x00\\x00") || strings.Contains(string(resp[:n]), "supported versions are (3/v3, 4/v4, 5/v5-beta)"):
		return "Cassandra"
	case strings.Contains(string(resp[:n]), "Apache") || strings.Contains(string(resp[:n]), "dubbo>"):
		return "Apache/Apache-dubbo"
	case strings.Contains(string(resp[:n]), "nginx"):
		return "Nginx"
	case strings.Contains(string(resp[:n]), "Microsoft-IIS"):
		return "Microsoft IIS"
	case strings.Contains(string(resp[:n]), "MariaDB"):
		return "MariaDB"
	case strings.Contains(string(resp[:n]), "Oracle") || strings.Contains(string(resp[:n]), "\\x00e\\x00\\x00\\x04") || strings.Contains(string(resp[:n]), "DESCRIPTION=") || strings.Contains(string(resp[:n]), "Oracle TNS Listener"):
		return "Oracle"
	case strings.Contains(string(resp[:n]), "MSSQL"):
		return "Microsoft SQL Server"
	case strings.Contains(string(resp[:n]), "Docker") || strings.Contains(string(resp[:n]), "\\x00\\x00\\x00\\x04\\x00"):
		return "Docker API"
	case strings.Contains(string(resp[:n]), "Samba"):
		return "Samba"
	case strings.Contains(string(resp[:n]), "XMPP") || strings.Contains(string(resp[:n]), "<?xml version='1.0'?><stream:stream"):
		return "XMPP"
	case strings.Contains(string(resp[:n]), "ESMTP") || strings.Contains(string(resp[:n]), "572 Relay not authorized") || strings.Contains(string(resp[:n]), "500 Permission denied - closing connection."):
		return "SMTP"
	case strings.Contains(string(resp[:n]), "IMAP") || strings.Contains(string(resp[:n]), "* OK"):
		return "IMAP"
	case strings.Contains(string(resp[:n]), "POP3") || strings.Contains(string(resp[:n]), "JARM:"):
		return "POP3"
	case strings.Contains(string(resp[:n]), "SNMP"):
		return "SNMP"
	case strings.Contains(string(resp[:n]), "Telnet") || strings.Contains(string(resp[:n]), "\\xff\\xfb\\x01\\xff\\xfb"):
		return "Telnet"
	case strings.Contains(string(resp[:n]), "LDAP") || strings.Contains(string(resp[:n]), "0\\x84\\x00\\x00\\x0bn\\x02") || strings.Contains(string(resp[:n]), "unable to set certificate file"):
		return "LDAP"
	case strings.Contains(string(resp[:n]), "X11") || strings.Contains(string(resp[:n]), "\\x01\\x00\\x0b\\x00") || strings.Contains(string(resp[:n]), "\\x00\\x16\\x0b\\x00\\x00"):
		return "X11"
	case strings.Contains(string(resp[:n]), "Zookeeper"):
		return "Zookeeper"
	case strings.Contains(string(resp[:n]), "memcached:") || strings.Contains(string(resp[:n]), "ERROR\nERROR"):
		return "Memcached"
	case strings.Contains(string(resp[:n]), "tftp") || strings.Contains(string(resp[:n]), "\\x00\\x05\\x00\\x05Unknown transfer ID\\x00"):
		return "TFTP"
	case strings.Contains(string(resp[:n]), "Kubernetes"):
		return "Kubernetes"
	case strings.Contains(string(resp[:n]), "Couchdb"):
		return "CouchDB"
	case strings.Contains(string(resp[:n]), "Postfix"):
		return "Postfix"
	case strings.Contains(string(resp[:n]), "SSL"):
		return "SSL/TLS"
	default:
		return identifyService(host, port)
	}
}
