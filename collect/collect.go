package collect

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type CookieConfig struct {
	Key   string `yaml:"key"`
	Value string `yaml:"value"`
}

type Config struct {
	Company string
	Cookies map[string]string
}

var config Config

func LoadCookies() error {
	filepath := "config/config.yaml"
	data, err := ioutil.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("\n[-] Failed to read the config file: %v", err)
	}

	var cookieConfigs struct {
		Config []CookieConfig `yaml:"config"`
	}

	err = yaml.Unmarshal(data, &cookieConfigs)
	if err != nil {
		return fmt.Errorf("[-] Failed to parse the config file: %v", err)
	}

	config.Cookies = make(map[string]string)
	for _, c := range cookieConfigs.Config {
		config.Cookies[c.Key] = c.Value
	}
	fmt.Println("\u001B[32m[+] Cookies loaded successfully.\u001B[0m")
	return nil
}

func SetOption(option, value string) error {
	switch strings.ToLower(option) {
	case "company":
		config.Company = value
	default:
		return errors.New("[-] Unknown option: " + option)
	}
	return nil
}

func Execute() error {
	err := LoadCookies()
	if err != nil {
		return err
	}

	if config.Company == "" {
		return errors.New("[-] Please set the company name first.")
	}

	aiqiChaCookie, ok := config.Cookies["AiQiCha"]
	if !ok || aiqiChaCookie == "" {
		return errors.New("[-] Missing AiQiCha cookie in configuration.")
	}

	companyEncoded := url.QueryEscape(config.Company)

	outputPath := fmt.Sprintf("result/collect/collect_%s.txt", config.Company)
	err = clearOutputFile(outputPath)
	if err != nil {
		return err
	}

	for page := 1; page <= 30; page++ {
		targetURL := fmt.Sprintf("https://aiqicha.baidu.com/s?q=%s&t=0&p=%d", companyEncoded, page)
		fmt.Printf("\u001B[32m[+] Crawling data for company: \u001B[1;35m%s\u001B[32m ...\u001B[0m\n", config.Company)

		client := &http.Client{}
		req, err := http.NewRequest("GET", targetURL, nil)
		if err != nil {
			return fmt.Errorf("[-] Failed to create request: %v", err)
		}

		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		req.Header.Set("Cookie", aiqiChaCookie)

		resp, err := client.Do(req)

		if err != nil {
			return fmt.Errorf("[-] Request failed: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("[-] Request failed with status code: %d", resp.StatusCode)
		}

		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("[-] Failed to read response body: %v", err)
		}

		decodedBody := decodeUnicodeString(string(body))

		stop := processResponse(decodedBody, page, outputPath)
		if stop {
			break
		}
		// 增加每次请求间隔 1 秒
		time.Sleep(3 * time.Second)
	}

	return nil
}

func processResponse(body string, page int, outputPath string) bool {
	pidRegex := regexp.MustCompile(`naParam\\":\\\"{\\\\\\\"pid\\\\\\\":\\\\\\\"(\d+)\\\\\\\"}`)
	pidMatches := pidRegex.FindAllStringSubmatch(body, -1)

	if len(pidMatches) == 0 {
		fmt.Printf("\u001B[31m[-] No PID values found on page %d. Stopping further requests.\u001B[0m\n", page)
		//如果没提取到pid 就停止循环
		return true
	}

	for _, match := range pidMatches {
		pid := match[1]
		//fmt.Printf("Page %d, PID: %s\n", page, pid)

		err := fetchCompanyDetails(pid, page, outputPath)
		if err != nil {
			fmt.Printf("[-] Failed to fetch details for PID %s: %v\n", pid, err)
		}
	}

	return false
}

func fetchCompanyDetails(pid string, page int, outputPath string) error {
	targetURL := fmt.Sprintf("https://aiqicha.baidu.com/company_detail_%s", pid)

	aiqiChaCookie := config.Cookies["AiQiCha"]

	client := &http.Client{}
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return fmt.Errorf("[-] Failed to create request: %v", err)
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
	req.Header.Set("Cookie", aiqiChaCookie)
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("[-] Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("[-] Request failed with status code: %d", resp.StatusCode)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("[-] Failed to read response body: %v", err)
	}

	decodedBody := decodeUnicodeString(string(body))
	decodedBody = cleanHTMLTags(decodedBody)

	err = extractCompanyInfo(decodedBody, page, pid, outputPath)
	if err != nil {
		return err
	}

	return nil
}

func extractCompanyInfo(body string, page int, pid string, outputPath string) error {
	telephoneRegex := regexp.MustCompile(`"telephone":\s*"([^"]+)"`)
	emailRegex := regexp.MustCompile(`"email":\s*"([^"]+)"`)
	taxNoRegex := regexp.MustCompile(`"taxNo":\s*"([^"]+)"`)
	websiteRegex := regexp.MustCompile(`"website":\s*"([^"]+)"`)
	headlineRegex := regexp.MustCompile(`"headline":\s*"([^"]+)"`)

	telephone := "null"
	email := "null"
	taxNo := "null"
	website := "null"
	companyName := "null"

	if match := telephoneRegex.FindStringSubmatch(body); len(match) > 1 {
		telephone = match[1]
	}
	if match := emailRegex.FindStringSubmatch(body); len(match) > 1 {
		email = match[1]
	}
	if match := taxNoRegex.FindStringSubmatch(body); len(match) > 1 {
		taxNo = match[1]
	}
	if match := websiteRegex.FindStringSubmatch(body); len(match) > 1 {
		website = match[1]
	}
	if match := headlineRegex.FindStringSubmatch(body); len(match) > 1 {
		companyName = match[1]
	}

	file, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("[-] Failed to open output file: %v", err)
	}
	defer file.Close()
	companyName = strings.TrimSuffix(companyName, " - 爱企查")
	file.WriteString(fmt.Sprintf("第%d页 PID：%s 公司名称：%s\n", page, pid, companyName))
	file.WriteString(fmt.Sprintf("[+] 电话: %s\n", telephone))
	file.WriteString(fmt.Sprintf("[+] 邮箱: %s\n", email))
	file.WriteString(fmt.Sprintf("[+] 网址: %s\n", website))
	file.WriteString(fmt.Sprintf("[+] 统一社会信用代码: %s\n", taxNo))
	file.WriteString(fmt.Sprintf("[!] 因爱企查平台检索特性，请您自行验证结果是否为您要查找的子(孙)公司: https://aiqicha.baidu.com/company_detail_%s\n\n", pid))

	fmt.Printf("\u001B[32m[+] Details for PID %s on page %d saved to %s\u001B[0m\n", pid, page, outputPath)

	return nil
}

func clearOutputFile(path string) error {
	dir := "result"
	// 检查并创建目录
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			return fmt.Errorf("[-] Failed to create directory %s: %v", dir, err)
		}
		fmt.Printf("\u001B[32m[+] Directory %s created successfully.\u001B[0m\n", dir)
	}

	// 创建或清空文件
	file, err := os.Create(path) // `os.Create` 如果文件已存在会清空内容
	if err != nil {
		return fmt.Errorf("[-] Failed to create or clear the file: %v", err)
	}
	defer file.Close()

	//fmt.Printf("\u001B[32m[+] Output file %s cleared and ready for new data.\n", path)
	return nil
}

func cleanHTMLTags(input string) string {
	htmlTagRegex := regexp.MustCompile(`<[^>]*>`)
	return htmlTagRegex.ReplaceAllString(input, "")
}

func decodeUnicodeString(input string) string {
	decodedStr := input
	for {
		escapedStr := regexp.MustCompile(`\\u[0-9a-fA-F]{4}`).FindString(decodedStr)
		if escapedStr == "" {
			break
		}
		runeValue, _ := strconv.ParseInt(escapedStr[2:], 16, 32)
		decodedStr = strings.Replace(decodedStr, escapedStr, string(rune(runeValue)), 1)
	}
	return decodedStr
}
