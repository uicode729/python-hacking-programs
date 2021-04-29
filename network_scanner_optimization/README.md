# Network Scanner (網路掃描器)

使用 python 腳本實現網路掃描器

## Setup

下載此 repository 並在本地運行

```bash
python network_scanner.py -t ip_address
```
ip_address 為目標的 IP 地址. 例: 10.0.2.1
此腳本還接受要掃描的一系列 IP 地址，只需要在 ip_address 字段中提供範圍。例：10.0.2.1/24 這告訴腳本從 10.0.2.1 開始掃描到 10.0.2.254