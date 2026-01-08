
🔐 PDF Password Cracker (Python)

A multi-threaded PDF password cracking tool using **pikepdf**, supporting both **wordlist-based attacks** and **charset brute-force generation**.
It uses `ThreadPoolExecutor` for concurrent password checking and `tqdm` for progress visualization.


🚀 Features

* 🔁 **Brute-force password generation** (custom charset, min/max length)
* 📚 **Wordlist mode** (read passwords from a file)
* ⚡ **Multi-threading support** (user-defined threads)
* ⏳ **Live progress bar** with tqdm
* 🛑 Stops instantly when the correct password is found
* ✔️ Clean, modular, and extensible code structure



## 📦 Requirements
Install dependencies:

  **pip install pikepdf tqdm**



🧠 Usage basic help:
 
  **python crack.py -h**



## 🔨 wordlist Mode
Use a wordlist file to attempt passwords:

  **python crack.py -pdf locked.pdf -w rockyou.txt -t 20**


Arguments:
| Flag            | Description           |
| --------------- | --------------------- |
| `-pdf`          | Path to protected PDF |
| `-w --wordlist` | Path to wordlist file |
| `-t --thread`   | Number of threads     |




## 🔨 Brute-Force Charset Mode
Generate passwords using a charset:

  **python crack.py -pdf locked.pdf -g -char abc123 -min 3 -max 5 -t 20**


Arguments:

| Flag                | Description                     |
| ------------------- | ------------------------------- |
| `-g --generate`     | Enable brute-force charset mode |
| `-char --charset`   | Characters to use               |
| `-min --min_length` | Minimum password length         |
| `-max --max_length` | Maximum password length         |
| `-t --thread`       | Threads to use                  |



---

## 🛡️ Legal Disclaimer

This tool is for **educational and authorized security testing only**.
Do **NOT** use it on PDFs that you do not own or have explicit permission to test.
The author is not responsible for misuse.

---

