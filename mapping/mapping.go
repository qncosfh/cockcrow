package mapping

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v2"
)

// MappingConfig stores configuration options for mapping
type MappingConfig struct {
	Companies []string
	Domains   []string
}

// AppConfig stores the configuration loaded from YAML
type AppConfig struct {
	Config []struct {
		Key   string `yaml:"key"`
		Value string `yaml:"value"`
	} `yaml:"config"`
}

// Global variables for configurations and API keys
var (
	config    MappingConfig
	appConfig AppConfig
	apiKeys   = map[string]string{}
	loaded    bool // To ensure LoadConfig is called once
)

// LoadConfig reads and parses the `config/config.yaml` file
func LoadConfig() error {
	if loaded {
		return nil
	}

	filepath := "config/config.yaml"
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read configuration file: %v", err)
	}

	if err := yaml.Unmarshal(data, &appConfig); err != nil {
		return fmt.Errorf("failed to parse configuration file: %v", err)
	}

	for _, key := range []string{"FoFa", "Hunter", "Quake"} {
		if value := getValueByKey(key); value != "" {
			apiKeys[key] = value
			logInfo(fmt.Sprintf("\u001B[32mLoaded key for \u001B[1;35m%s \u001B[32msuccessfully.\u001B[0m", key))
		} else {
			logWarning(fmt.Sprintf("Key for %s not found in the configuration file.", key))
		}
	}

	loaded = true
	return nil
}

// getValueByKey retrieves the value for a given key from appConfig
func getValueByKey(key string) string {
	for _, entry := range appConfig.Config {
		if entry.Key == key {
			return entry.Value
		}
	}
	return ""
}

// SetOption allows dynamic setting of configuration options
func SetOption(option, value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value cannot be empty")
	}

	values := strings.Split(value, ",")
	for i := range values {
		values[i] = strings.TrimSpace(values[i])
	}

	switch strings.ToLower(option) {
	case "company":
		config.Companies = append(config.Companies, values...)
	case "domain":
		config.Domains = append(config.Domains, values...)
	default:
		return fmt.Errorf("invalid option: %s. Supported options are 'company' or 'domain'", option)
	}
	return nil
}

// Execute performs the mapping task based on the current configuration
func Execute() error {
	if !loaded {
		if err := LoadConfig(); err != nil {
			return fmt.Errorf("configuration loading failed: %v", err)
		}
	}

	if len(config.Companies) == 0 && len(config.Domains) == 0 {
		return errors.New("no configuration provided: please set 'company' or 'domain'")
	}

	logInfo("\033[32mExecuting mapping task with the following configuration.\033[0m")

	for apiName, key := range apiKeys {
		logInfo(fmt.Sprintf("\u001B[32mUsing \u001B[1;35m%s \u001B[32mAPI...\u001B[0m", apiName))
		if err := executeQueries(apiName, key); err != nil {
			logError(fmt.Sprintf("Failed to execute queries for %s: %v", apiName, err))
		}
	}

	logInfo("\u001B[32mMapping task completed successfully.\u001B[0m")
	return nil
}

// executeQueries determines the input type and executes appropriate queries
func executeQueries(apiName, key string) error {
	queries := generateQueries(apiName)
	for _, query := range queries {
		if err := queryAPI(apiName, key, query); err != nil {
			logError(fmt.Sprintf("Error querying %s with query [%s]: %v", apiName, query, err))
		}
	}
	return nil
}

// generateQueries generates API-specific queries based on configuration
func generateQueries(apiName string) []string {
	var queries []string
	if len(config.Companies) > 0 {
		for _, company := range config.Companies {
			switch apiName {
			case "FoFa":
				queries = append(queries, fmt.Sprintf(`title="%s" && country="CN" && (body="管理" || body="后台" || body="登录" || body="用户名" || body="密码" || body="验证码" || body="系统" || body="账号" || body="忘记密码" || title="管理" || title="后台" || title="登录" || title="邮件" || title="教务" || title="注册" || title="访客")`, company))
			case "Hunter":
				queries = append(queries, fmt.Sprintf(`web.title="%s"&& ip.country="中国" && (web.body="登录"||web.body="密码"||web.body="系统"||web.body="忘记密码")`, company))
			case "Quake":
				queries = append(queries, fmt.Sprintf(`title:"%s" && country:china && service:"http" (response:"管理" || response:"后台" || response:"登录" || response:"用户名" || response:"密码" || response:"验证码" || response:"系统" || response:"账号" || response:"忘记密码")`, company))
			}
		}
	}
	if len(config.Domains) > 0 {
		for _, domain := range config.Domains {
			switch apiName {
			case "FoFa":
				queries = append(queries, fmt.Sprintf(`domain="%s" && country="CN"`, domain))
			case "Hunter":
				queries = append(queries, fmt.Sprintf(`domain="%s" && ip.country="中国"`, domain))
			case "Quake":
				queries = append(queries, fmt.Sprintf(`domain:"%s" && country:china`, domain))
			}
		}
	}
	return queries
}

// queryAPI sends a query to the specified API and processes the result
func queryAPI(apiName, key, query string) error {
	var url string
	var req *http.Request
	var err error

	switch apiName {
	case "FoFa":
		encodedQuery := base64.StdEncoding.EncodeToString([]byte(query))
		url = fmt.Sprintf("https://fofa.info/api/v1/search/all?key=%s&qbase64=%s", key, encodedQuery)
		req, err = http.NewRequest("GET", url, nil)
	case "Hunter":
		encodedQuery := base64.URLEncoding.EncodeToString([]byte(query))
		url = fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=100", key, encodedQuery)
		req, err = http.NewRequest("GET", url, nil)
	case "Quake":
		jsonBody := map[string]interface{}{
			"query":        query,
			"start":        0,
			"size":         100,
			"ignore_cache": false,
			"latest":       true,
			"shortcuts":    []string{"610ce2adb1a2e3e1632e67b1"},
		}
		jsonData, err := json.Marshal(jsonBody)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %v", err)
		}
		req, err = http.NewRequest("POST", "https://quake.360.net/api/v3/search/quake_service", bytes.NewBuffer(jsonData))
		req.Header.Set("X-QuakeToken", key)
		req.Header.Set("Content-Type", "application/json")
	default:
		return fmt.Errorf("unknown API name: %s", apiName)
	}

	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to query %s API: %v", apiName, err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}
	//调试正则	logInfo(string(body))
	processAPIResponse(apiName, query, string(body))
	return nil
}

// processAPIResponse processes the API response and saves results to files
func processAPIResponse(apiName, input, data string) {
	var ipRegex, domainRegex, urlRegex *regexp.Regexp

	switch apiName {

	case "FoFa":
		//ipRegex = regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
		//domainRegex = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		//urlRegex = regexp.MustCompile(`^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[\w/-]*)*$`)
		ipRegex = regexp.MustCompile(`((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)`)
		domainRegex = regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
		urlRegex = regexp.MustCompile(`(https?://[^\s",]+)`)
	case "Hunter":
		ipRegex = regexp.MustCompile(`"ip":\s*"([^"]*)"`)
		domainRegex = regexp.MustCompile(`"domain":\s*"([^"]*)"`)
		urlRegex = regexp.MustCompile(`"url":\s*"([^"]*)"`)

	case "Quake":
		ipRegex = regexp.MustCompile(`"ip":\s*"((?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-fA-F0-9:]+)"`)
		domainRegex = regexp.MustCompile(`"cname":\s*\[\s*"([^"]+)"`)
		urlRegex = regexp.MustCompile(`"http_load_url":\s*\[\s*"([^"]+)"`)
	}

	// Save results for each regex if they exist
	if ipRegex != nil {
		saveMatchesToFile(data, "mapping_ip.txt", ipRegex)
	}
	if domainRegex != nil {
		saveMatchesToFile(data, "mapping_domain.txt", domainRegex)
	}
	if urlRegex != nil {
		saveMatchesToFile(data, "mapping_url.txt", urlRegex)
	}
}

// saveMatchesToFile saves regex matches to a file (appends to existing content)
func saveMatchesToFile(data, fileName string, re *regexp.Regexp) {
	matches := re.FindAllStringSubmatch(data, -1)
	results := extractMatches(matches)

	// 去重
	uniqueResults := removeDuplicates(results)

	// 校验IP、URL、Domain格式
	validResults := []string{}
	for _, result := range uniqueResults {
		switch fileName {
		case "mapping_ip.txt":
			if isValidIP(result) {
				validResults = append(validResults, result)
			}
		case "mapping_url.txt":
			if isValidURL(result) {
				validResults = append(validResults, result)
			}
		case "mapping_domain.txt":
			if isValidDomain(result) {
				validResults = append(validResults, result)
			}
		}
	}
	dir := fmt.Sprintf("result/mapping/%s-%s", config.Companies, config.Domains)
	//outputDir := "result/%smapping"
	outputDir := dir
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		logError(fmt.Sprintf("Failed to create output directory: %v", err))
		return
	}

	filePath := filepath.Join(outputDir, fileName)

	// 打开文件（追加模式），不存在则创建
	file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logError(fmt.Sprintf("Failed to open file %s: %v", filePath, err))
		return
	}
	defer file.Close()

	// 将结果写入文件（追加内容）
	if _, err := file.WriteString(strings.Join(validResults, "\n") + ""); err != nil {
		logError(fmt.Sprintf("Failed to write to file %s: %v", filePath, err))
	}
}

// isValidIP checks if a string is a valid IP address
func isValidIP(ip string) bool {
	// Regular expression for validating IPv4 and IPv6 addresses
	ipRegex := regexp.MustCompile(`^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	ipv6Regex := regexp.MustCompile(`([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})`)

	return ipRegex.MatchString(ip) || ipv6Regex.MatchString(ip)
}

// isValidURL checks if a string is a valid URL
func isValidURL(url string) bool {
	// Regular expression for validating URL format (basic validation)
	urlRegex := regexp.MustCompile(`^(https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[\w/-]*)*$`)
	return urlRegex.MatchString(url)
}

// isValidDomain checks if a string is a valid domain
func isValidDomain(domain string) bool {
	// Regular expression for validating domain format
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(domain)
}

// removeDuplicates removes duplicate strings from a slice
func removeDuplicates(input []string) []string {
	uniqueSet := make(map[string]struct{})
	var result []string

	for _, item := range input {
		if _, exists := uniqueSet[item]; !exists {
			uniqueSet[item] = struct{}{}
			result = append(result, item)
		}
	}

	return result
}

// extractMatches extracts relevant data from regex matches
func extractMatches(matches [][]string) []string {
	var results []string
	for _, match := range matches {
		if len(match) > 1 {
			results = append(results, match[1])
		}
	}
	return results
}

// logInfo logs info level messages
func logInfo(message string) {
	fmt.Println("\u001B[32m[+]", message)
}

// logWarning logs warning level messages
func logWarning(message string) {
	fmt.Println("\u001B[33m[!]", message)
}

// logError logs error level messages
func logError(message string) {
	fmt.Println("\u001B[31m[-]", message)
}
