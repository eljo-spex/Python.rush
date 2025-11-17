PDF password cracker (python) 
A multi-threaded PDF password cracking tool using pikepdf, supporting both wordlist-based attacks and charset brute-force generation.
It uses ThreadPoolExecutor for concurrent password checking and tqdm for progress visualization.

Features
🔁 Brute-force password generation (custom charset, min/max length)
📚 Wordlist mode (read passwords from a file)
⚡ Multi-threading support (user-defined threads)
⏳ Live progress bar with tqdm
🛑 Stops instantly when the correct password is found
✔️ Clean, modular, and extensible code structure

Requirements
install dependencies: pip install pikepdf tqdm

usage
basic help : python crack.py -h

Wordlist Mode
Use a wordlist file to attempt passwords: python crack.py -pdf locked.pdf -w rockyou.txt -t 20

Brute-Force Charset Mode
Generate passwords using a charset : python crack.py -pdf locked.pdf -g -char abc123 -min 3 -max 5 -t 20

Legal Disclaimer
This tool is for educational and authorized security testing only.
Do NOT use it on PDFs that you do not own or have explicit permission to test.
The author is not responsible for misuse
