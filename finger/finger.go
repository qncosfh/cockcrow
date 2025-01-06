package finger

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"gopkg.in/yaml.v2"
)

// Fingerprint holds the information about detected technologies or services
type Fingerprint struct {
	CMS string
}

type HeaderMatch struct {
	CMS     string   `yaml:"CMS"`
	Keyword []string `yaml:"keyword"`
}

type Md5Match struct {
	CMS  string `yaml:"CMS"`
	Hash string `yaml:"Hash"`
}

type Config struct {
	Target      string
	Targets     []string
	Type        string // New field for specifying type
	Timeout     int
	Concurrency int
}

var config Config

func SetOption(option, value string) error {
	switch option {
	case "target":
		config.Target = normalizeURL(value)
	case "targets":
		lines := strings.Split(value, "\n")
		for _, line := range lines {
			config.Targets = append(config.Targets, normalizeURL(line))
		}
	case "type":
		config.Type = strings.ToLower(strings.TrimSpace(value))
	case "concurrency":
		concurrency, err := parseInt(value)
		if err != nil {
			return fmt.Errorf("invalid concurrency value: %v", err)
		}
		config.Concurrency = concurrency
	default:
		return fmt.Errorf("unknown option: %s", option)
	}
	return nil
}

func normalizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}
	return strings.TrimRight(rawURL, "/")
}

func parseInt(value string) (int, error) {
	var result int
	_, err := fmt.Sscanf(value, "%d", &result)
	return result, err
}

func Execute() error {
	if config.Target == "" && len(config.Targets) == 0 {
		return fmt.Errorf("no target specified")
	}

	var targets []string
	if config.Target != "" {
		targets = []string{config.Target}
	} else {
		targets = config.Targets
	}

	if config.Concurrency == 0 {
		config.Concurrency = 300
	}

	bar := progressbar.NewOptions(len(targets),
		progressbar.OptionSetDescription("Scanning targets"),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(50),
		progressbar.OptionClearOnFinish(),
	)

	tasks := make(chan string, len(targets))
	var wg sync.WaitGroup

	client := &http.Client{
		Timeout: time.Duration(config.Timeout) * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range tasks {
				if err := fingerprintTarget(client, target, bar); err != nil {
					fmt.Printf("\nError scanning target %s: %v\n", target, err)
				}
			}
		}()
	}

	for _, target := range targets {
		tasks <- target
	}
	close(tasks)

	wg.Wait()
	bar.Finish()
	return nil
}

func fingerprintTarget(client *http.Client, target string, bar *progressbar.ProgressBar) error {
	defer bar.Add(1)

	resp, err := client.Get(target)
	if err != nil {
		return fmt.Errorf("failed to fetch target: %v", err)
	}
	defer resp.Body.Close()

	switch config.Type {
	case "md5":
		return runMD5Matching(client, target)
	case "header":
		return runHeaderMatching(resp.Header)
	default:
		// Default logic: both header and MD5 matching
		if err := runHeaderMatching(resp.Header); err == nil {
			return nil
		}
		return runMD5Matching(client, target)
	}
}

func runHeaderMatching(headers http.Header) error {
	if fingerprint := matchHeaders(headers); fingerprint != nil {
		fmt.Printf("\n\u001B[32m[+] Header fingerprint detected: \u001B[1;35m%s\u001B[0m\n", fingerprint.CMS)
		return nil
	}
	return fmt.Errorf("no header fingerprint detected")
}

func runMD5Matching(client *http.Client, target string) error {
	paths, err := readLines("dict/finger/Md5_Path/Finger_Md5_Path.txt")
	if err != nil {
		return fmt.Errorf("failed to read MD5 path file: %v", err)
	}

	for _, path := range paths {
		url := target + path
		hash, err := fetchAndHash(client, url)
		if err != nil {
			continue
		}
		if fingerprint := matchMD5(hash); fingerprint != nil {
			fmt.Printf("\n\u001B[32m[+] MD5 fingerprint detected: \u001B[1;35m%s\u001B[0m\n", fingerprint.CMS)
			return nil
		}
	}
	return fmt.Errorf("no MD5 fingerprint detected")
}

func matchHeaders(headers http.Header) *Fingerprint {
	file, err := os.Open("dict/finger/finger_header.yaml")
	if err != nil {
		fmt.Printf("\nFailed to open finger_header.yaml: %v\n", err)
		return nil
	}
	defer file.Close()

	var rules struct {
		Header []HeaderMatch `yaml:"Header"`
	}
	if err := yaml.NewDecoder(file).Decode(&rules); err != nil {
		fmt.Printf("\nFailed to decode finger_header.yaml: %v\n", err)
		return nil
	}

	for _, rule := range rules.Header {
		for _, keyword := range rule.Keyword {
			re := regexp.MustCompile("(?i)" + regexp.QuoteMeta(keyword))

			for _, values := range headers {
				for _, value := range values {
					if re.MatchString(value) {
						return &Fingerprint{CMS: rule.CMS}
					}
				}
			}
		}
	}
	return nil
}

func fetchAndHash(client *http.Client, url string) (string, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request for URL %s: %v", url, err)
	}
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Pragma", "no-cache")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to fetch URL %s: %v", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("non-200 HTTP response: %d for URL %s", resp.StatusCode, url)
	}

	hash := md5.New()
	if _, err := io.Copy(hash, resp.Body); err != nil {
		return "", fmt.Errorf("failed to read response body for URL %s: %v", url, err)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func matchMD5(hash string) *Fingerprint {
	file, err := os.Open("dict/finger/finger_md5.yaml")
	if err != nil {
		fmt.Printf("\nFailed to open finger_md5.yaml: %v\n", err)
		return nil
	}
	defer file.Close()

	var rules struct {
		Md5 []Md5Match `yaml:"Md5"`
	}
	if err := yaml.NewDecoder(file).Decode(&rules); err != nil {
		fmt.Printf("\nFailed to decode finger_md5.yaml: %v\n", err)
		return nil
	}

	for _, rule := range rules.Md5 {
		if strings.EqualFold(rule.Hash, hash) {
			return &Fingerprint{CMS: rule.CMS}
		}
	}
	return nil
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
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
