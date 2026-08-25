package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

var banner = `

      | |/ ____| |/ /           | | | |              | |           
      | | (___ | ' / ___ _   _  | |_| |_   _ _ __  __| |_ ___ _ __ 
  _   | |\___ \|  < / _ \ | | | |  _  | | | | '_ \/ _` | __/ _ \ '__|

 | |__| |____) | . \  __/ |_| | | | | | |_| | | | | (_| | ||  __/ |   
  \____/|_____/|_|\_\___|\__, | |_| |_|\__,_|_| |_|\__,_|\__\___|_|   
                          __/ |                                       
                         |___/                                        {
  
 [!] JSKeyHunter: Ultimate Secret & Token Extractor
 [!] File/List Mode | 100+ Optimized Patterns | Zero Noise
 ----------------------------------------------------------
`

var secretPatterns = map[string]*regexp.Regexp{
	"AWS Access Key":      regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"AWS Secret/Key":      regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key|aws_access_key_id|secret_access_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{20,40}['"]?`),
	"Azure/GCP Secret":    regexp.MustCompile(`(?i)(azure_tenant|google_private_key|google_server_key|cloud_api_key)\s*[:=]\s*['"]?[a-zA-Z0-9\-_\.]{20,100}['"]?`),
	"GitHub Token":        regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	"GitHub Secret/Key":   regexp.MustCompile(`(?i)(github_token|github_api_key|github_secret|gh_token)\s*[:=]\s*['"]?[a-zA-Z0-9_\-]{20,64}['"]?`),
	"GitLab Token":        regexp.MustCompile(`glpat-[a-zA-Z0-9\-]{20}`),
	"GitLab Secret":       regexp.MustCompile(`(?i)(gitlab_token|gitlab_private_token)\s*[:=]\s*['"]?[a-zA-Z0-9\-]{20,64}['"]?`),
	"Stripe Key":          regexp.MustCompile(`(?i)(stripe_key|stripe_secret|sk_live_|sk_test_)[a-zA-Z0-9]{24,34}`),
	"PayPal Key/Token":    regexp.MustCompile(`(?i)(paypal_secret|paypal_token|paypal_key_live|paypal_key_sb)\s*[:=]\s*['"]?[a-zA-Z0-9\-_\.]{20,100}['"]?`),
	"Slack Token/Webhook": regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,250}|https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,10}/[a-zA-Z0-9_]{24}`),
	"Twilio SID/Token":    regexp.MustCompile(`(?i)(twilio_account_sid|twilio_api_key|twilio_secret|sid_token)\s*[:=]\s*['"]?[A-Za-z0-9]{20,64}['"]?`),
	"SendGrid/Mailgun":    regexp.MustCompile(`(?i)(sendgrid_api_key|mailgun_api_key|mailgun_priv_key|mg_api_key)\s*[:=]\s*['"]?[A-Za-z0-9\-_\.]{20,64}['"]?`),
	"Telegram Bot":        regexp.MustCompile(`[0-9]{8,10}:[a-zA-Z0-9_-]{35}`),
	"Facebook/Meta":       regexp.MustCompile(`(?i)(facebook_secret|fb_secret|facebook_access_token)\s*[:=]\s*['"]?[a-f0-9]{32,64}['"]?`),
	"Twitter/X":           regexp.MustCompile(`(?i)(twitter_api_secret|twitter_bearer_token|twitter_secret)\s*[:=]\s*['"]?[a-zA-Z0-9%]{20,64}['"]?`),
	"Google API/Maps":     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}|(?i)(google_maps_api_key|google_secret)\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{20,64}['"]?`),
	"Firebase Token":      regexp.MustCompile(`(?i)(firebase_custom_token|firebase_id_token)\s*[:=]\s*['"]?[a-zA-Z0-9\-_\.]{40,100}['"]?`),
	"Algolia/Mapbox":      regexp.MustCompile(`(?i)(algolia_api_key|algolia_admin_key|mapbox_access_token)\s*[:=]\s*['"]?[a-zA-Z0-9\-_]{20,64}['"]?|pk\.[a-zA-Z0-9\-_]{60,100}`),
	"DB Credentials":      regexp.MustCompile(`(?i)(db_password|dbpasswd|mysql_root_password|postgres_env_postgres_password|redis_password)\s*[:=]\s*['"]?[^\s'"]{6,}['"]?`),
	"Generic Password":    regexp.MustCompile(`(?i)(admin_pass|password|passwd|pwd|secret|token)\s*[:=]\s*['"]?[^\s'"]{8,}['"]?`),
	"JWT Token":           regexp.MustCompile(`ey[A-Za-z0-9_-]+\.ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	"Private Key":         regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----`),
	"Niche API Keys":      regexp.MustCompile(`(?i)(shodan_api_key|datadog_api_key|zendesk_api_token|onesignal_api_key|wompi_auth_bearer|browserstack_access_key)\s*[:=]\s*['"]?[a-zA-Z0-9\-_\.]{20,100}['"]?`),
}

var (
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
)

type Finding struct {
	File    string
	Type    string
	Secret  string
	LineNum int
}

func main() {
	fmt.Print(cyan(banner))

	filePtr := flag.String("f", "", "Scan a single file (.js, .txt, .json, etc.)")
	listPtr := flag.String("l", "", "Scan a list of files from a .txt file")
	outPtr := flag.String("o", "", "Output file (e.g., target.txt)")
	flag.Parse()

	if *filePtr == "" && *listPtr == "" {
		fmt.Printf("%s Usage: JSKeyHunter -f <file> OR JSKeyHunter -l <list.txt> [-o target.txt]\n", red("[-] Error: Input is required."))
		os.Exit(1)
	}

	var findings []Finding

	if *filePtr != "" {
		findings = scanFile(*filePtr)
	} else if *listPtr != "" {
		findings = scanList(*listPtr)
	}

	uniqueFindings := deduplicate(findings)

	if len(uniqueFindings) > 0 {
		fmt.Println("\n" + cyan("========== SECRETS EXTRACTED =========="))
		for _, f := range uniqueFindings {
			fmt.Printf("[%s] %s\n", cyan(f.Type), yellow(f.Secret))
			fmt.Printf("   -> %s (Line %d)\n\n", f.File, f.LineNum)
		}
		fmt.Println(cyan("=========================================="))
		fmt.Printf("%s Total Unique Secrets: %s\n", green("[+]"), green(fmt.Sprintf("%d", len(uniqueFindings))))
	} else {
		fmt.Printf("\n%s No secrets found in the provided file(s).\n", yellow("[*]"))
	}

	if *outPtr != "" && len(uniqueFindings) > 0 {
		saveToFile(uniqueFindings, *outPtr)
		fmt.Printf("%s Results saved to: %s\n", green("[+]"), *outPtr)
	}
}

func scanList(listPath string) []Finding {
	var allFindings []Finding
	file, err := os.Open(listPath)
	if err != nil {
		fmt.Printf("%s Cannot open list file: %v\n", red("[-] Error:"), err)
		return allFindings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		targetFile := strings.TrimSpace(scanner.Text())
		if targetFile != "" && !strings.HasPrefix(targetFile, "#") {
			allFindings = append(allFindings, scanFile(targetFile)...)
		}
	}
	return allFindings
}

func scanFile(filePath string) []Finding {
	var findings []Finding
	file, err := os.Open(filePath)
	if err != nil {
		return findings
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 1
	for scanner.Scan() {
		line := scanner.Text()
		for pName, regex := range secretPatterns {
			for _, match := range regex.FindAllString(line, -1) {
				findings = append(findings, Finding{
					File: filePath, Type: pName, Secret: cleanSecret(match), LineNum: lineNum,
				})
			}
		}
		lineNum++
	}
	return findings
}

func cleanSecret(s string) string {
	s = strings.Trim(s, `"' `)
	if idx := strings.IndexAny(s, ":="); idx != -1 {
		val := strings.TrimSpace(s[idx+1:])
		val = strings.Trim(val, `"' `)
		if len(val) > 4 {
			return val
		}
	}
	return s
}

func deduplicate(f []Finding) []Finding {
	seen := make(map[string]bool)
	var unique []Finding
	for _, item := range f {
		key := item.Type + "|" + item.Secret
		if !seen[key] {
			seen[key] = true
			unique = append(unique, item)
		}
	}
	return unique
}

func saveToFile(findings []Finding, filename string) {
	file, _ := os.Create(filename)
	defer file.Close()
	for _, f := range findings {
		fmt.Fprintf(file, "[%s] %s | %s (Line %d)\n", f.Type, f.Secret, f.File, f.LineNum)
	}
}
