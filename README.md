# OSFingerprint  
Effortlessly detect remote operating systems, leveraging Nmap's OS detection capabilities.  

---

## Prerequisites  
Ensure that **Python 3** is installed on your machine.  

---

## Installation  
1. Download the **osfp** tool from the [releases page](https://github.com/michalbarer/OSFingerprint/releases/download/v0.1.0/os_fingerprint-0.1.0-py3-none-any.whl).  
2. Navigate to your download directory and install the package using:  
   ```bash
   pip install os_fingerprint-0.1.0-py3-none-any.whl
    ```
---
## Usage:
```bash
osfp -h [host] [-op [open port] -op [open port] ...] [-cp [closed port] -cp [closed port] ...] [-s] [-lop [port scan limit]] [-n [number of results]] [-v]
```

### Command Options:  
| Option                             | Description                                                                                  |  
|------------------------------------|----------------------------------------------------------------------------------------------|  
| `-h, --host TEXT`                  | **(Required)** Target host's IP address.                                                    |  
| `-op, --open-ports INTEGER`        | List of open ports to include in the scan.                                                  |  
| `-cp, --closed-ports INTEGER`      | List of closed ports to include in the scan.                                                |  
| `-s, --skip-common-ports BOOL`     | Skips scanning common ports if open and closed ports are provided.                          |  
| `-lop, --limit-open-ports INTEGER` | Sets a limit for the number of open ports to scan (default: 3).                             |  
| `-n, --num-results INTEGER`        | Specifies how many of the top results to display (default: 10).                             |  
| `-v, --verbose BOOL`               | Enables verbose output.                                                                     |  
| `--help`                           | Displays the help menu and exits.                                                           |  

---
## Examples  
### 1. Basic Scan  
Scan the target `scanme.nmap.org` using default settings:  
```bash
osfp -h scanme.nmap.org
````

### 2. Verbose Mode with Limited Results
Scan scanme.nmap.org in verbose mode and display the top 5 results:
```bash
osfp -h scanme.nmap.org -n 5 -v
```

### 3. Faster Scan with Limited Open Ports
Limit the scan to 1 open port for faster results (less accurate):
```bash
osfp -h scanme.nmap.org -lop 1
```

### 4. Custom Port Configuration
If you know specific open and closed ports for the target, specify them to skip common port scanning:
```bash
osfp -h scanme.nmap.org -op 22 -op 80 -cp 21 -cp 8080 -s
```
> **Note:**  
> - Using the `-s` flag requires both `-op` and `-cp` to be provided. If `-s` is used without specifying ports, a default scan will still occur.  
> - Passing `-op` and `-cp` don't override the default scan (`-s`), but rather add to it.


---
## Development Mode  
For contributing or modifying the tool, use the following steps:  

### 1. Install dependencies:  
   ```bash
   pip install -r requirements.txt
   ```
### 2. Install the package in editable mode:  
   ```bash
   pip install --editable .
   ```