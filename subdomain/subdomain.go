package subdomain

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
)

type Config struct {
	Domain    string
	Level     int
	DictPath  string
	DictWords []string
}

var config Config

// getDefaultDictPath returns the default path for the dictionary file
func getDefaultDictPath() string {
	execPath, _ := os.Getwd()
	return filepath.Join(execPath, "dict/subdomain/subdomain_dict1.txt")
}

// loadDictionary reads subdomain words from the dictionary file
func loadDictionary() error {
	if config.DictPath == "" {
		config.DictPath = getDefaultDictPath()
	}

	file, err := os.Open(config.DictPath)
	if err != nil {
		return fmt.Errorf("failed to open dictionary file: %s", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	config.DictWords = nil
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			config.DictWords = append(config.DictWords, word)
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading dictionary file: %s", err)
	}
	return nil
}

// SetOption allows setting configuration options dynamically
func SetOption(option, value string) error {
	switch strings.ToLower(option) {
	case "domain":
		config.Domain = value
	case "level":
		level, err := strconv.Atoi(value)
		if err != nil || level < 1 {
			return fmt.Errorf("invalid level: must be an integer greater than 0")
		}
		config.Level = level
	case "dict":
		config.DictPath = value
	default:
		return fmt.Errorf("unknown option: %s", option)
	}
	return nil
}

// Execute starts the subdomain scanning process
func Execute() error {
	if config.Domain == "" {
		return fmt.Errorf("domain is not set")
	}
	if config.Level < 1 {
		return fmt.Errorf("level must be greater than 0")
	}
	if err := loadDictionary(); err != nil {
		return fmt.Errorf("error loading dictionary: %s", err)
	}

	fmt.Printf("Starting subdomain scan for %s using dictionary: %s\n", config.Domain, config.DictPath)
	subdomains := generateAllSubdomains()

	bar := progressbar.Default(int64(len(subdomains)), "Scanning subdomains")
	var wg sync.WaitGroup
	var mu sync.Mutex
	liveSubdomains := make([]string, 0)

	client := &http.Client{Timeout: 5 * time.Second}
	sem := make(chan struct{}, 300) // Limit concurrent goroutines to 20

	results := make(chan string, len(subdomains))  // Buffered channel for results
	errors := make(chan struct{}, len(subdomains)) // Channel for tracking progress bar updates

	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(sd string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if validateDNS(sd) && isAlive(sd, client) {
				mu.Lock()
				liveSubdomains = append(liveSubdomains, sd)
				mu.Unlock()
				results <- sd
			}
			errors <- struct{}{}
		}(subdomain)
	}

	// Progress bar updater
	go func() {
		for range errors {
			bar.Add(1)
		}
	}()

	wg.Wait()
	close(errors) // Close the errors channel to stop progress updates
	close(results)

	fmt.Printf("\nSubdomain scan complete. Found %d live subdomains:\n", len(liveSubdomains))
	for _, subdomain := range liveSubdomains {
		highlightSubdomain(subdomain)
	}
	return nil
}

// generateAllSubdomains generates subdomains for all dictionary words
func generateAllSubdomains() []string {
	subdomains := make([]string, 0)
	queue := []string{config.Domain}

	for level := 1; level <= config.Level; level++ {
		nextQueue := make([]string, 0)
		for _, base := range queue {
			for _, word := range config.DictWords {
				subdomain := fmt.Sprintf("%s.%s", word, base)
				subdomains = append(subdomains, subdomain)
				nextQueue = append(nextQueue, subdomain)
			}
		}
		queue = nextQueue
	}
	return subdomains
}

// isAlive checks if a subdomain is reachable
func isAlive(domain string, client *http.Client) bool {
	url := fmt.Sprintf("http://%s", domain)
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// validateDNS checks if the subdomain exists in DNS
func validateDNS(domain string) bool {
	_, err := net.LookupHost(domain)
	return err == nil
}

// highlightSubdomain prints the subdomain in highlighted format
func highlightSubdomain(subdomain string) {
	highlight := color.New(color.FgGreen).Add(color.Bold)
	highlight.Printf("[LIVE] %s\n", subdomain)
}
