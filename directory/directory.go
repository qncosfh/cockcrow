package directory

import (
	"bufio"
	"errors"
	"fmt"
	"github.com/schollz/progressbar/v3"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Target  string
	Targets string
	Type    string
	Level   int
	Dict    string
}

var config Config

// SetOption 设置扫描配置
func SetOption(option, value string) error {
	switch strings.ToLower(option) {
	case "target":
		normalizedURL, err := normalizeURL(value)
		if err != nil {
			return fmt.Errorf("invalid target URL: %v", err)
		}
		config.Target = normalizedURL
	case "targets":
		config.Targets = value
	case "type":
		config.Type = value
	case "level":
		level, err := strconv.Atoi(value)
		if err != nil {
			return errors.New("level must be an integer")
		}
		config.Level = level
	case "dict":
		config.Dict = value
	default:
		return fmt.Errorf("unknown option: %s", option)
	}
	return nil
}

// Execute 开始目录扫描
func Execute() error {
	if config.Target == "" && config.Targets == "" {
		return errors.New("target or targets must be set")
	}

	if config.Dict == "" && config.Type == "" {
		return errors.New("either dict or type must be specified")
	}

	targets, err := getTargets()
	if err != nil {
		return err
	}

	paths, err := getDictionaryPaths()
	if err != nil {
		return err
	}
	//初始化进度条
	totalTasks := len(targets) * len(paths)
	bar := progressbar.NewOptions(totalTasks,
		progressbar.OptionSetDescription("Scanning..."),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(50),
		progressbar.OptionClearOnFinish(),      //完成后清除
		progressbar.OptionSetWriter(os.Stderr), //固定在标准错误输出
	)

	logChan := make(chan string, 100)
	done := make(chan struct{})

	// 日志打印协程
	go func() {
		defer close(done) // 确保日志打印完成后通知主协程退出
		for log := range logChan {
			fmt.Println(log)
		}
	}()

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, 300)

	for _, target := range targets {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			scanTarget(target, paths, config.Level, bar, semaphore, logChan)
		}(target)
	}

	wg.Wait()
	close(logChan) // 确保日志通道关闭
	<-done         // 等待日志协程完成
	return nil
}

// normalizeURL 标准化 URL
func normalizeURL(input string) (string, error) {
	input = strings.TrimSpace(input)
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "http://" + input
	}

	parsedURL, err := url.Parse(input)
	if err != nil {
		return "", err
	}

	parsedURL.Path = ""
	parsedURL.RawQuery = ""
	parsedURL.Fragment = ""

	// 移除尾部的 `/`
	normalized := strings.TrimRight(parsedURL.String(), "/")
	return normalized, nil
}

// getTargets 获取扫描目标
func getTargets() ([]string, error) {
	var targets []string
	if config.Target != "" {
		targets = append(targets, config.Target)
	}
	if config.Targets != "" {
		fileTargets, err := readLines(config.Targets)
		if err != nil {
			return nil, fmt.Errorf("failed to read targets file: %v", err)
		}
		for _, t := range fileTargets {
			normalizedURL, err := normalizeURL(t)
			if err != nil {
				fmt.Printf("Skipping invalid target URL: %s\n", t)
				continue
			}
			targets = append(targets, normalizedURL)
		}
	}
	return targets, nil
}

// getDictionaryPaths 获取字典路径
func getDictionaryPaths() ([]string, error) {
	// 如果用户自定义了字典，则直接使用用户提供的字典路径
	if config.Dict != "" {
		// 获取绝对路径
		absPath, err := filepath.Abs(config.Dict)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve absolute path for dict file: %v", err)
		}
		fmt.Printf("Using dictionary file at: %s\n", absPath)

		paths, err := readLines(absPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read dictionary file: %v", err)
		}
		return paths, nil
	}

	// 如果没有指定字典文件路径，根据 type 来获取默认字典
	dict := getDictPathForType(config.Type)
	if dict == "unknown" {
		return nil, fmt.Errorf("unsupported type: %s", config.Type)
	}

	// 获取绝对路径
	absPath, err := filepath.Abs(dict)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve absolute path for default dict file: %v", err)
	}
	fmt.Printf("Using default dictionary file at: %s\n", absPath)

	paths, err := readLines(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read dictionary file: %v", err)
	}

	return paths, nil
}

// getDictPathForType 根据 type 返回相应的字典文件路径
func getDictPathForType(typeStr string) string {
	switch strings.ToLower(typeStr) {
	case "jsp":
		return "dict/jsp/directory_jsp_dict.txt"
	case "jspx":
		return "dict/jspx/directory_jspx_dict.txt"
	case "asp":
		return "dict/asp/directory_asp_dict.txt"
	case "aspx":
		return "dict/aspx/directory_aspx_dict.txt"
	case "php":
		return "dict/php/directory_php_dict.txt"
	case "mdb":
		return "dict/mdb/directory_mdb_dict.txt"
	case "dir":
		return "dict/dir/directory_dir_dict.txt"
	case "backup":
		return "dict/backup/directory_backup_dict.txt"
	default:
		return "unknown"
	}
}

// scanTarget 对单个目标进行扫描
func scanTarget(target string, paths []string, level int, bar *progressbar.ProgressBar, semaphore chan struct{}, logChan chan string) {
	if level == 0 {
		return
	}

	var wg sync.WaitGroup
	var mutex sync.Mutex
	validPaths := make([]string, 0)

	for _, path := range paths {
		wg.Add(1)
		semaphore <- struct{}{}
		go func(path string) {
			defer wg.Done()
			defer func() { <-semaphore }()

			// 处理拼接，确保不会出现多余的 `//`
			url := strings.TrimRight(target, "/") + path
			statusCode, length, title, redirectURL, err := isURLReachable(url)
			if err == nil && (statusCode >= 200 && statusCode < 300 || statusCode >= 300 && statusCode < 400 || statusCode == 401 || statusCode == 403) {
				// 处理 3xx 重定向
				if redirectURL != "" {
					logChan <- fmt.Sprintf("\n\033[31m[!] Redirected: \u001B[1;35m%s \u001B[31m| \u001B[31mRedirected to: %s\033[0m",
						url, redirectURL)
				} else {
					// 输出正常的有效路径
					// 加锁，安全地更新 validPaths
					mutex.Lock()
					validPaths = append(validPaths, path)
					mutex.Unlock()
					logChan <- fmt.Sprintf("\n\033[32m[+] Found: \u001B[1;35m%s \u001B[32m| Status: \u001B[1;35m%d \u001B[32m| Length: \u001B[1;35m%d \u001B[32m| Title: \u001B[1;35m%s\033[0m",
						url, statusCode, length, title)
				}
			}
			bar.Add(1)
		}(path)
	}
	wg.Wait()

	// 递归扫描有效路径
	for _, validPath := range validPaths {
		// 处理递归扫描的目标路径，确保路径拼接正确
		newTarget := strings.TrimRight(target, "/") + validPath
		scanTarget(newTarget+"/", paths, level-1, bar, semaphore, logChan)
	}
}

// isURLReachable 检查 URL 是否可访问
func isURLReachable(url string) (int, int, string, string, error) {
	client := &http.Client{
		// 禁用自动重定向
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 返回重定向的 URL
			return fmt.Errorf("redirected to %s", req.URL.String())
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, 0, "", "", err
	}

	// 设置随机请求头
	randomHeaders := getRandomHeader()
	for key, values := range randomHeaders {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		// 如果遇到重定向，err 会包含重定向 URL
		if strings.Contains(err.Error(), "redirected to") {
			// 提取重定向 URL
			redirectURL := err.Error()[len("redirected to "):]
			return resp.StatusCode, 0, "", redirectURL, nil
		}
		return 0, 0, "", "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, 0, "", "", err
	}

	title := extractTitle(body)
	return resp.StatusCode, len(body), title, "", nil
}

// extractTitle 提取 HTML 的标题
func extractTitle(data []byte) string {
	content := string(data)
	start := strings.Index(content, "<title>")
	end := strings.Index(content, "</title>")
	if start != -1 && end != -1 && start < end {
		return strings.TrimSpace(content[start+len("<title>") : end])
	}

	// 备用方案：尝试从常见的 meta 标签中提取标题相关内容
	metaStart := strings.Index(content, "<meta name=\"description\"")
	if metaStart != -1 {
		metaEnd := strings.Index(content[metaStart:], ">")
		if metaEnd != -1 {
			metaTag := content[metaStart : metaStart+metaEnd]
			descStart := strings.Index(metaTag, "content=\"")
			if descStart != -1 {
				descEnd := strings.Index(metaTag[descStart+len("content=\""):], "\"")
				if descEnd != -1 {
					return strings.TrimSpace(metaTag[descStart+len("content=\"") : descStart+len("content=\"")+descEnd])
				}
			}
		}
	}

	// 备用方案 2：提取 <h1> 或 <h2> 等重要标题
	h1Start := strings.Index(content, "<h1>")
	h1End := strings.Index(content, "</h1>")
	if h1Start != -1 && h1End != -1 && h1Start < h1End {
		return strings.TrimSpace(content[h1Start+len("<h1>") : h1End])
	}

	h2Start := strings.Index(content, "<h2>")
	h2End := strings.Index(content, "</h2>")
	if h2Start != -1 && h2End != -1 && h2Start < h2End {
		return strings.TrimSpace(content[h2Start+len("<h2>") : h2End])
	}

	// 如果以上方法均失败，则返回 "N/A"
	return "N/A"
}

// readLines 从文件中读取每行数据
func readLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// getRandomHeader 生成随机请求头
func getRandomHeader() http.Header {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:90.0) Gecko/20100101 Firefox/90.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (Linux; Android 11; SM-A217F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.210 Mobile Safari/537.36",
	}

	rand.Seed(time.Now().UnixNano())
	randomUserAgent := userAgents[rand.Intn(len(userAgents))]

	headers := http.Header{}
	headers.Set("User-Agent", randomUserAgent)
	headers.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	headers.Set("Accept-Language", "en-US,en;q=0.5")

	return headers
}
