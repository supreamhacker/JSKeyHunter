# 🚀 JSKeyHunter

**The Ultimate File-Based Secret & Token Extractor.**

`JSKeyHunter` is a high-performance, zero-noise cybersecurity tool written in **Golang**. Instead of scanning entire folders, it precisely targets specific files (`.js`, `.txt`, `.json`, `.env`) or a text file containing a list of file paths, extracting exposed API keys, tokens, and secrets using 100+ highly optimized regex patterns.

<img width="1042" height="577" alt="image" src="https://github.com/user-attachments/assets/abc3072d-7f09-4845-bac7-b4dec5537ecb" />


## ✨ Features

- 🎯 **Precise File Targeting:** Scan single files or a `.txt` list of files (No noisy folder scanning).
- 🔍 **100+ Optimized Patterns:** Covers AWS, Stripe, GitHub, Slack, Google, Firebase, PayPal, Twilio, DB credentials, and more.
- ⚡ **Blazing Fast:** Pre-compiled regex and 1MB buffer support for heavily minified files.
- 🤫 **Zero Noise Output:** Clean terminal output. Only shows actual findings.
- 🧠 **Smart Deduplication:** Ensures the same secret isn't reported multiple times.

## 📦 Installation

Install `jskeyhunter` directly from GitHub with a single command:

```bash
go install github.com/supreamhacker/jskeyhunter@latest

(Ensure your $GOPATH/bin or $HOME/go/bin is in your system's PATH)

🛠️ Usage
1. Scan a Single File (.js, .txt, .json, etc.)

jskeyhunter -f app.js -o target.txt
jskeyhunter -f config.json -o target.txt

2. Scan a List of Files from a .txt File (Recommended)
Create a paths.txt file with one file path per line:

Then run:

jskeyhunter -l paths.txt -o target.txt

3. View Help Menu

jskeyhunter -h

Help Output:

Usage of jskeyhunter:
  -f string
        Scan a single file (.js, .txt, .json, etc.)
  -l string
        Scan a list of files from a .txt file
  -o string
        Output file (e.g., target.txt)


⚠️ Disclaimer & Ethical Use

jskeyhunter is intended strictly for Educational Purposes, Authorized Bug Bounty Hunting, and Internal Security Auditing.
DO NOT use this tool to scan targets you do not own or have explicit written permission to test.
The authors are not responsible for any misuse or damage caused by this tool. Use it responsibly. 🛡️

📜 License

This project is licensed under the MIT License.

[![Go Report Card](https://goreportcard.com/badge/github.com/supreamhacker/jskeyhunter)](https://goreportcard.com/report/github.com/supreamhacker/jskeyhunter)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

