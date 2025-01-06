package auxiliary

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config 配置结构体
type Config struct {
	AttackIP []string
}

var (
	config   Config
	basePath string
)

// SetBasePath 设置基础路径
func SetBasePath(path string) {
	basePath = path
}

// SetOption 设置配置项
func SetOption(option, value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value cannot be empty")
	}

	switch strings.ToLower(option) {
	case "attack_ip":
		// 设置攻击IP，可以是多个IP，用逗号分隔
		config.AttackIP = strings.Split(value, ",")
		for i := range config.AttackIP {
			config.AttackIP[i] = strings.TrimSpace(config.AttackIP[i])
		}
	default:
		return fmt.Errorf("unknown option: %s", option)
	}
	return nil
}

// Execute 执行任务
func Execute() error {
	if basePath == "" {
		return errors.New("basePath is not set")
	}

	if len(config.AttackIP) == 0 {
		return errors.New("no configuration provided: please set 'attack_ip'")
	}

	var exploitDirs []string
	// 如果用户未指定类型，默认扫描所有目录
	fmt.Println("No type specified, scanning all directories under WebPoc...")
	files, err := listAllFiles(basePath)
	if err != nil {
		return fmt.Errorf("failed to list files under basePath: %v", err)
	}
	exploitDirs = files

	// 执行任务并保存结果
	if err := runTasksAndSaveResults(exploitDirs); err != nil {
		return fmt.Errorf("failed to execute tasks: %v", err)
	}

	return nil
}

// runTasksAndSaveResults 运行任务并保存结果
func runTasksAndSaveResults(dirs []string) error {
	resultsDir := filepath.Join("result", "auxiliary")
	if err := os.MkdirAll(resultsDir, 0755); err != nil {
		return fmt.Errorf("failed to create results directory: %v", err)
	}

	outputFile := filepath.Join(resultsDir, "auxiliary_commands.txt")
	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %v", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, dir := range dirs {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		// 使用攻击IP生成每个命令
		for _, ip := range config.AttackIP {
			command := fmt.Sprintf("[%s] Executing attack on IP: %s, Directory: %s\n", timestamp, ip, dir)
			writer.WriteString(command)
			fmt.Print(command) // 打印到控制台
		}
	}

	fmt.Printf("Results saved to %s\n", outputFile)
	return nil
}

// readLines 读取文件内容为字符串数组
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
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}

// listAllFiles 列出路径下的所有文件
func listAllFiles(basePath string) ([]string, error) {
	var files []string
	err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}
