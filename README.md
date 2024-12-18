# OSFingerprint
Detect remote Operating System quickly


## Usage
### Prerequisites:
```bash
pip install -r requirements.txt
pip install --editable .
```
### Use the tool:
```bash
osfp -h [host] -sp [start port] -ep [end port] [-l [port scan limit]]
```
### Example:
```bash
osfp -h scanme.nmap.org -sp 80 -ep 100 -l 10
```
