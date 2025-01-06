package proxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// ProxyConfig 结构体用于存储代理模块的配置
type ProxyConfig struct {
	Target string
	Port   string
	Type   string
	User   string
	Pass   string
}

var config ProxyConfig
var globalHTTPClient *http.Client // 全局 HTTP 客户端，用于其他模块使用代理

// SetOption 用于设置代理模块的选项
func SetOption(option, value string) error {
	switch strings.ToLower(option) {
	case "target":
		config.Target = value
	case "port":
		config.Port = value
	case "type":
		if value != "socks5" && value != "http" {
			return errors.New("invalid proxy type; must be 'socks5' or 'http'")
		}
		config.Type = value
	case "user":
		config.User = value
	case "pass":
		config.Pass = value
	default:
		return fmt.Errorf("unknown option: %s", option)
	}
	return nil
}

// TestProxy 用于测试代理是否可用并返回 IP 地址
func TestProxy() (string, error) {
	if config.Target == "" || config.Port == "" || config.Type == "" {
		return "", errors.New("missing required options: target, port, and type must be set")
	}

	proxyURL := buildProxyURL()
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return "", fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedURL),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
	}

	resp, err := client.Get("http://httpbin.org/ip")
	if err != nil {
		return "", fmt.Errorf("proxy test failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy test failed: received status code %d", resp.StatusCode)
	}

	// 解析响应，提取 IP 地址
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("failed to parse response JSON: %v", err)
	}

	origin, ok := result["origin"].(string)
	if !ok {
		return "", errors.New("failed to extract IP address from response")
	}

	return origin, nil
}

// Execute 用于启动代理并设置全局代理
func Execute() error {
	// 测试代理是否可用并获取 IP 地址
	ip, err := TestProxy()
	if err != nil {
		return err
	}

	proxyURL := buildProxyURL()
	parsedURL, err := url.Parse(proxyURL)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %v", err)
	}

	transport := &http.Transport{
		Proxy: http.ProxyURL(parsedURL),
	}
	globalHTTPClient = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// 设置环境变量代理（跨平台支持）
	setProxyEnv(proxyURL)

	// 注册终止处理，确保退出时代理失效
	registerShutdownHandler()

	fmt.Printf("Proxy service started successfully! \nYour IP address: \033[1;35m%s\u001B[0m\n", ip)
	return nil
}

// GetHTTPClient 返回全局 HTTP 客户端
func GetHTTPClient() *http.Client {
	if globalHTTPClient == nil {
		globalHTTPClient = &http.Client{
			Timeout: 10 * time.Second,
		}
	}
	return globalHTTPClient
}

// ClearProxy 清除代理配置
func ClearProxy() error {
	globalHTTPClient = nil
	clearProxyEnv()

	// Windows 专用代理清除
	if err := clearProxyWindows(); err != nil {
		return err
	}

	fmt.Println("Proxy cleared successfully!")
	return nil
}

// clearProxyWindows 清除 Windows 系统代理设置
func clearProxyWindows() error {
	cmd := exec.Command("cmd", "/C", `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /f`)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to clear proxy on Windows: %v", err)
	}
	cmd = exec.Command("cmd", "/C", `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /f`)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to clear proxy server on Windows: %v", err)
	}
	return nil
}

// clearProxyEnv 清除环境变量中的代理设置
func clearProxyEnv() {
	envs := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"}
	for _, env := range envs {
		os.Unsetenv(env)
	}
}

// setProxyEnv 设置环境变量中的代理
func setProxyEnv(proxyURL string) {
	// 设置 HTTP/HTTPS 代理
	os.Setenv("HTTP_PROXY", proxyURL)
	os.Setenv("HTTPS_PROXY", proxyURL)
	os.Setenv("http_proxy", proxyURL)
	os.Setenv("https_proxy", proxyURL)

	// 如果代理类型是 SOCKS5，设置 ALL_PROXY
	if config.Type == "socks5" {
		os.Setenv("ALL_PROXY", proxyURL)
	}

	// PowerShell 设置代理
	var powershellCommand strings.Builder
	powershellCommand.WriteString(fmt.Sprintf("$env:HTTP_PROXY='%s'; $env:HTTPS_PROXY='%s'; $env:http_proxy='%s'; $env:https_proxy='%s'", proxyURL, proxyURL, proxyURL, proxyURL))
	if config.Type == "socks5" {
		powershellCommand.WriteString(fmt.Sprintf("; $env:ALL_PROXY='%s'", proxyURL))
	}
	cmd := exec.Command("powershell", "-Command", powershellCommand.String())
	err := cmd.Run()
	if err != nil {
		return
		//fmt.Printf("Failed to set environment variables in PowerShell: %v\n", err)
	}

	// CMD 设置代理
	var cmdCommand strings.Builder
	cmdCommand.WriteString(fmt.Sprintf("set HTTP_PROXY=%s && set HTTPS_PROXY=%s && set http_proxy=%s && set https_proxy=%s", proxyURL, proxyURL, proxyURL, proxyURL))
	if config.Type == "socks5" {
		cmdCommand.WriteString(fmt.Sprintf(" && set ALL_PROXY=%s", proxyURL))
	}
	cmd = exec.Command("cmd", "/C", cmdCommand.String())
	err = cmd.Run()
	if err != nil {
		//fmt.Printf("Failed to set environment variables in CMD: %v\n", err)
		return
	}
}

// buildProxyURL 构造代理 URL
func buildProxyURL() string {
	proxyURL := fmt.Sprintf("%s://%s:%s", config.Type, config.Target, config.Port)
	if config.User != "" && config.Pass != "" {
		proxyURL = fmt.Sprintf("%s://%s:%s@%s:%s", config.Type, config.User, config.Pass, config.Target, config.Port)
	}
	return proxyURL
}

// registerShutdownHandler 注册终止信号的处理函数
func registerShutdownHandler() {
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		ClearProxy()
		os.Exit(0)
	}()
}
