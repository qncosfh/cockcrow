package fishing

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"github.com/skip2/go-qrcode"
	"log"
	"math/rand"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

// Config holds configuration options.
type Config struct {
	Text    string // Path to the configuration file
	Target  string // Single target email address
	Targets string // File containing multiple target email addresses
	Annex   string // Path to a single attachment file
}

// Global configuration variable
var config Config

// Default configuration paths
const (
	defaultTextFile  = "config/fishing/email_config.txt"
	defaultAnnexFile = "config/fishing/钓鱼附件/test.docx"
)

// User pool for sender address spoofing
var usernamePool = []string{"hr", "system", "admin", "administrator", "root", "portal", "manager", "superadmin", "yunwei", "IT"}

// SetOption sets configuration options.
func SetOption(option, value string) error {
	switch option {
	case "text":
		config.Text = value
	case "target":
		config.Target = value
	case "targets":
		config.Targets = value
	case "annex":
		config.Annex = value
	default:
		return fmt.Errorf("invalid configuration option: %s", option)
	}
	return nil
}

// Execute executes the email-sending logic.
func Execute() error {
	if config.Text == "" {
		config.Text = defaultTextFile
		log.Printf("No config file specified. Using default: %s\n", defaultTextFile)
	}

	if config.Annex == "" {
		config.Annex = defaultAnnexFile
		log.Printf("No annex file specified. Using default: %s\n", defaultAnnexFile)
	}

	loginEmail, password, smtpHost, smtpPorts, fromEmail, subject, body, err := parseConfigFile(config.Text)
	if err != nil {
		return fmt.Errorf("failed to parse config file: %v", err)
	}

	if fromEmail == "" {
		fromEmail = generateRandomFromEmail(loginEmail)
		log.Printf("FromEmail not specified. Using generated: %s\n", fromEmail)
	}

	if strings.Contains(body, "二维码") {
		body = handleQRCode(body)
	}

	var recipients []string
	if config.Target != "" {
		recipients = []string{config.Target}
	} else {
		recipients, err = readRecipients(config.Targets)
		if err != nil {
			return fmt.Errorf("failed to read recipient list: %v", err)
		}
	}

	attachments, err := getAttachments(config.Annex)
	if err != nil {
		return fmt.Errorf("failed to read attachment: %v", err)
	}

	for _, recipient := range recipients {
		log.Printf("Sending email to %s...\n", recipient)
		fromEmail = checkDomainForSpoofing(fromEmail, recipient)

		err := sendEmailWithMultiplePorts(loginEmail, password, smtpHost, smtpPorts, fromEmail, recipient, subject, body, attachments)
		if err != nil {
			log.Printf("Failed to send email to %s: %v", recipient, err)
		} else {
			log.Printf("Email sent successfully to %s\n", recipient)
		}
	}
	return nil
}

func generateRandomFromEmail(loginEmail string) string {
	rand.Seed(time.Now().UnixNano())
	username := usernamePool[rand.Intn(len(usernamePool))]
	domain := strings.Split(loginEmail, "@")[1]
	return fmt.Sprintf("%s@%s", username, domain)
}

func checkDomainForSpoofing(fromEmail, recipient string) string {
	recipientDomain := strings.Split(recipient, "@")[1]

	// Check if the domain has valid MX or TXT records
	_, mxErr := net.LookupMX(recipientDomain)
	_, txtErr := net.LookupTXT(recipientDomain)

	if mxErr != nil && txtErr != nil {
		log.Printf("Domain %s may be spoofed (no MX or TXT records).\n", recipientDomain)
		senderUsername := usernamePool[rand.Intn(len(usernamePool))]
		fromEmailParts := strings.Split(fromEmail, "@")
		fromEmail = fmt.Sprintf("%s@%s", senderUsername, fromEmailParts[1])
	} else {
		log.Printf("Domain %s has valid MX or TXT records, spoofing is less likely.\n", recipientDomain)
	}
	return fromEmail
}

func parseConfigFile(filename string) (loginEmail, password, smtpHost string, smtpPorts []string, fromEmail, subject, body string, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", "", "", nil, "", "", "", err
	}
	defer file.Close()

	configMap := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.Contains(line, ":<") {
			continue
		}
		parts := strings.SplitN(line, ":<", 2)
		if len(parts) != 2 {
			return "", "", "", nil, "", "", "", fmt.Errorf("invalid config line: %s", line)
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSuffix(parts[1], ">")
		configMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return "", "", "", nil, "", "", "", err
	}

	loginEmail = configMap["EmailAccount"]
	password = configMap["EmailPassword"]
	smtpHost = configMap["SMTPServer"]
	smtpPorts = strings.Split(configMap["SMTPPorts"], "/")
	fromEmail = configMap["FromEmail"]
	subject = configMap["Subject"]
	body = configMap["Body"]

	return
}

func readRecipients(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var recipients []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		recipients = append(recipients, scanner.Text())
	}
	return recipients, nil
}

func getAttachments(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory; expected a file", path)
	}
	return []string{path}, nil
}

func handleQRCode(body string) string {
	url := extractURL(body)
	if url == "" {
		return body
	}

	qrFile := "config/fishing/qrcode.png"
	err := qrcode.WriteFile(url, qrcode.Medium, 256, qrFile)
	if err != nil {
		log.Fatalf("Failed to generate QR code: %v", err)
	}

	qrData, err := os.ReadFile(qrFile)
	if err != nil {
		log.Fatalf("Failed to read QR code file: %v", err)
	}
	qrBase64 := base64.StdEncoding.EncodeToString(qrData)

	body += fmt.Sprintf(`
		<br><img src="data:image/png;base64,%s" alt="QR Code">
	`, qrBase64)

	return body
}

func extractURL(body string) string {
	words := strings.Fields(body)
	for _, word := range words {
		if strings.HasPrefix(word, "http://") || strings.HasPrefix(word, "https://") {
			return word
		}
	}
	return ""
}

func sendEmailWithMultiplePorts(loginEmail, password, smtpHost string, smtpPorts []string, fromEmail, toEmail, subject, body string, attachments []string) error {
	var lastError error
	for _, port := range smtpPorts {
		err := sendEmail(loginEmail, password, smtpHost, port, fromEmail, toEmail, subject, body, attachments)
		if err == nil {
			return nil
		}
		lastError = err
	}
	return fmt.Errorf("failed to send on all ports: %v\n", lastError)
}

func sendEmail(loginEmail, password, smtpHost, smtpPort, fromEmail, toEmail, subject, body string, attachments []string) error {
	msg := bytes.Buffer{}
	msg.WriteString(fmt.Sprintf("From: %s\n", fromEmail))
	msg.WriteString(fmt.Sprintf("To: %s\n", toEmail))
	msg.WriteString(fmt.Sprintf("Subject: %s\n", subject))
	msg.WriteString("MIME-Version: 1.0\n")
	msg.WriteString("Content-Type: multipart/mixed; boundary=\"boundary\"\n\n")
	msg.WriteString("--boundary\n")
	msg.WriteString("Content-Type: text/html; charset=\"utf-8\"\n\n")
	msg.WriteString(body)

	for _, attachment := range attachments {
		err := addAttachment(&msg, attachment)
		if err != nil {
			return err
		}
	}

	auth := smtp.PlainAuth("", loginEmail, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, loginEmail, []string{toEmail}, msg.Bytes())
}

func addAttachment(msg *bytes.Buffer, filepath string) error {
	file, err := os.Open(filepath)
	if err != nil {
		return fmt.Errorf("failed to open attachment file: %v", err)
	}
	defer file.Close()

	fileStat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file stats: %v", err)
	}

	fileName := fileStat.Name()
	fileBytes, err := os.ReadFile(filepath)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	msg.WriteString("\n--boundary\n")
	msg.WriteString(fmt.Sprintf("Content-Type: application/octet-stream; name=\"%s\"\n", fileName))
	msg.WriteString("Content-Transfer-Encoding: base64\n")
	msg.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\n\n", fileName))
	msg.WriteString(base64.StdEncoding.EncodeToString(fileBytes))
	msg.WriteString("\n")

	return nil
}
