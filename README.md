## Laporan Implementasi SOAR pada SIEM Wazuh
## DDoS Detection & Automated Mitigation menggunakan Wazuh Active Response

|Nama Kelompok                | NRP         |
|-----------------------------|-------------|
| Balqis Sani Sabillah        |  5027241002 | 
| Mey Rosalina                |  5027241004 |
| Dina Rahmadani              |  5027241065 | 



<img width="1374" height="774" alt="image" src="https://github.com/user-attachments/assets/ad8081e4-63a7-4030-a1ed-70e392bd77f1" />

---

## 1. Latar Belakang

Pada proyek sebelumnya (MIKS), telah diimplementasikan Wazuh SIEM untuk mendeteksi serangan HTTP Flood DDoS pada server NGINX melalui monitoring log secara real-time. Mitigasi dilakukan secara **manual** menggunakan perintah `iptables`.

Pada proyek ini, sistem dikembangkan dengan menambahkan kapabilitas **SOAR (Security Orchestration, Automation and Response)** menggunakan fitur **Active Response** bawaan Wazuh. Dengan SOAR, proses deteksi dan mitigasi DDoS menjadi **otomatis** — tanpa intervensi manual.

---

## 2. Tujuan

- Mengintegrasikan SOAR ke dalam framework SIEM Wazuh yang sudah ada
- Mengotomatisasi respons terhadap serangan HTTP Flood DDoS
- Membuat custom Active Response script (Python) untuk auto-block IP attacker
- Memverifikasi bahwa SOAR berjalan end-to-end: deteksi → trigger → mitigasi otomatis

---

## 3. Arsitektur Sistem

```
┌─────────────────────────────────────────────────────────────────┐
│                        AZURE VM                                  │
│                                                                   │
│  ┌─────────────┐    HTTP Flood     ┌──────────────────────────┐  │
│  │  ATTACKER   │ ─────────────────▶│     NGINX Web Server     │  │
│  │ (ApacheBench│                   │   /var/log/nginx/        │  │
│  └─────────────┘                   │      access.log          │  │
│                                    └────────────┬─────────────┘  │
│                                                 │ log stream      │
│                                    ┌────────────▼─────────────┐  │
│                                    │      WAZUH AGENT         │  │
│                                    │  (monitor access.log)    │  │
│                                    └────────────┬─────────────┘  │
│                                                 │ alerts+events   │
│                                    ┌────────────▼─────────────┐  │
│                                    │     WAZUH MANAGER        │  │
│                                    │  - Rules Engine          │  │
│                                    │  - Rule 100097 (level 3) │  │
│                                    │  - Rule 100100 (level 12)│  │
│                                    └────────────┬─────────────┘  │
│                                                 │ trigger AR      │
│                         ┌───────────────────────▼──────────────┐ │
│                         │        SOAR: Active Response          │ │
│                         │  custom-ddos-mitigation.py            │ │
│                         │  → iptables -I INPUT -s <IP> -j DROP  │ │
│                         └───────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

**Perbedaan dengan SIEM sebelumnya:**

| Aspek | SIEM (sebelumnya) | SIEM + SOAR (sekarang) |
|---|---|---|
| Deteksi DDoS | ✅ Otomatis | ✅ Otomatis |
| Mitigasi (block IP) | ❌ Manual (`sudo iptables ...`) | ✅ Otomatis (Active Response) |
| Waktu respons | Menit (tergantung admin) | Detik (real-time) |
| Intervensi manusia | Diperlukan | Tidak diperlukan |

---

## 4. Konfigurasi Sistem

### 4.1 Spesifikasi Environment

- **Platform:** Microsoft Azure VM
- **OS:** Ubuntu 24.04
- **SIEM:** Wazuh v4.7.5 (All-in-One: Manager + Indexer + Dashboard)
- **Web Server:** NGINX 1.24.0
- **Install method:** `curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh && sudo bash ./wazuh-install.sh -a`

---

### 4.2 Custom Rules Deteksi DDoS

File: `/var/ossec/etc/rules/local_rules.xml`

```xml
<group name="web,ddos,local">

  <!-- Override rule ignore simple URLs agar tidak di-skip oleh rule 31108 -->
  <rule id="100097" level="3">
    <if_sid>31108</if_sid>
    <description>Web simple query override for DDoS detection</description>
  </rule>

  <!-- Override base web access rule -->
  <rule id="100098" level="3">
    <if_sid>31100</if_sid>
    <description>Web access event override</description>
  </rule>

  <!-- DDoS Detection: trigger jika 1 IP kirim 20+ request dalam 10 detik -->
  <rule id="100100" level="12" frequency="20" timeframe="10" ignore="60">
    <if_matched_sid>100097</if_matched_sid>
    <same_source_ip />
    <description>Possible HTTP Flood DDoS attack detected from $(srcip)</description>
    <group>ddos,attack,</group>
  </rule>

  <!-- DDoS Detection fallback dari rule 100098 -->
  <rule id="100101" level="12" frequency="20" timeframe="10" ignore="60">
    <if_matched_sid>100098</if_matched_sid>
    <same_source_ip />
    <description>Possible HTTP Flood DDoS attack detected from $(srcip)</description>
    <group>ddos,attack,</group>
  </rule>

</group>
```

**Penjelasan rule:**
- Rule **100097**: Override rule 31108 yang mengabaikan simple URL (`/`), agar request ke `/` tetap diproses oleh rule engine
- Rule **100100**: Trigger DDoS alert jika 1 IP mengirim ≥20 request dalam 10 detik, level 12 (critical), ignore 60 detik agar tidak spam alert

---

### 4.3 Konfigurasi SOAR di ossec.conf

File: `/var/ossec/etc/ossec.conf`

Tambahkan blok berikut di dalam `<ossec_config>`:

```xml
<!-- SOAR: Definisi command Active Response -->
<command>
  <name>custom-ddos-mitigation</name>
  <executable>custom-ddos-mitigation.py</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<!-- SOAR: Trigger Active Response saat Rule 100100 fired -->
<active-response>
  <disabled>no</disabled>
  <command>custom-ddos-mitigation</command>
  <location>local</location>
  <rules_id>100100</rules_id>
  <timeout>600</timeout>
</active-response>
```

**Penjelasan:**
- `rules_id>100100`: Active Response hanya trigger saat rule DDoS fired
- `timeout>600`: IP attacker di-unblock otomatis setelah 600 detik (10 menit)
- `location>local`: Script dijalankan di node yang sama dengan agent

---

### 4.4 SOAR Script: custom-ddos-mitigation.py

File: `/var/ossec/active-response/bin/custom-ddos-mitigation.py`

```python
#!/var/ossec/framework/python/bin/python3
import sys
import json
import subprocess
import datetime
import os

LOG_FILE = "/var/ossec/logs/custom-soar.log"

def log_action(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.datetime.now()} - {msg}\n")

def main():
    # Membaca alert JSON yang dikirim oleh Wazuh Manager
    input_str = sys.stdin.read()
    if not input_str:
        log_action("ERROR: No input received from Wazuh")
        return

    try:
        data = json.loads(input_str)
    except Exception as e:
        log_action(f"ERROR parsing JSON: {e} | Raw input: {input_str[:200]}")
        return

    command  = data.get("command")
    alert    = data.get("parameters", {}).get("alert", {})
    src_ip   = alert.get("data", {}).get("srcip")
    rule_id  = alert.get("rule", {}).get("id", "unknown")
    ts       = alert.get("timestamp", "unknown")

    log_action(f"Received command='{command}' rule_id={rule_id} src_ip={src_ip} timestamp={ts}")

    if not src_ip:
        log_action("ERROR: Source IP tidak ditemukan. Eksekusi dibatalkan.")
        return

    # Whitelist: jangan block IP lokal
    whitelist = ["127.0.0.1", "::1", "localhost"]
    if src_ip in whitelist:
        log_action(f"SKIPPED: IP {src_ip} ada di whitelist, tidak diblokir.")
        return

    # Deteksi IPv4 atau IPv6
    is_ipv6      = ":" in src_ip
    iptables_cmd = "ip6tables" if is_ipv6 else "iptables"

    if command == "add":
        action    = "-I"   # Insert di posisi pertama
        log_label = "BLOCKING"
    elif command == "delete":
        action    = "-D"   # Delete rule
        log_label = "UNBLOCKING"
    else:
        log_action(f"ERROR: Unknown command '{command}'")
        return

    # Susun dan eksekusi perintah iptables
    cmd = [iptables_cmd, action, "INPUT", "-s", src_ip, "-j", "DROP"]

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        log_action(f"SUCCESS [{log_label}]: {' '.join(cmd)}")
    except subprocess.CalledProcessError as e:
        log_action(f"FAILED [{log_label}]: {' '.join(cmd)} | stderr: {e.stderr.strip()}")
    except FileNotFoundError:
        log_action(f"ERROR: {iptables_cmd} tidak ditemukan di sistem")

if __name__ == "__main__":
    main()
```

**Permission script:**
```bash
sudo chmod 750 /var/ossec/active-response/bin/custom-ddos-mitigation.py
sudo chown root:wazuh /var/ossec/active-response/bin/custom-ddos-mitigation.py
```

---

## 5. Simulasi Serangan DDoS

Simulasi dilakukan menggunakan ApacheBench:

```bash
ab -n 3000 -c 200 http://20.6.131.76/
```

**Penjelasan parameter:**
- `-n 3000` → total 3000 request
- `-c 200` → 200 request concurrent (bersamaan)
- Target IP `20.6.131.76` → IP publik Azure VM

---

## 6. Hasil & Verifikasi SOAR

### 6.1 Rule 100100 Fired

Output `wazuh-logtest` setelah menerima 20+ request dari IP yang sama:

```
**Phase 3: Completed filtering (rules).
        id: '100100'
        level: '12'
        description: 'Possible HTTP Flood DDoS attack detected from 20.6.131.76'
        groups: '['web', 'ddos', 'localddos', 'attack']'
        firedtimes: '1'
        frequency: '20'
        mail: 'True'
**Alert to be generated.
```

### 6.2 SOAR Script Dieksekusi Otomatis

Output `/var/ossec/logs/custom-soar.log`:

```
2026-05-25 10:13:52.648707 - Received command='add' rule_id=100100 src_ip=20.6.131.76 timestamp=2026-05-25T10:05:00.403+0000
2026-05-25 10:13:52.651292 - SUCCESS [BLOCKING]: iptables -I INPUT -s 20.6.131.76 -j DROP
```

### 6.3 IP Attacker Ter-block di Firewall

Output `sudo iptables -L INPUT -n -v | grep DROP`:

```
9   540 DROP  0  --  *  *  20.6.131.76  0.0.0.0/0
```

### 6.4 Koneksi Attacker Terputus

ApacheBench mengalami timeout setelah IP diblokir:

```
apr_pollset_poll: The timeout specified has expired (70007)
```

---

## 7. Alur Kerja SOAR End-to-End

```
1. ApacheBench kirim 3000 request ke 20.6.131.76
          ↓
2. NGINX catat semua request di /var/log/nginx/access.log
          ↓
3. Wazuh Agent baca access.log secara real-time
          ↓
4. Rule 100097 fired (override rule ignore simple URL)
          ↓
5. 20+ request dari IP yang sama dalam 10 detik
          ↓
6. Rule 100100 fired → Level 12 (Critical) → Alert generated
          ↓
7. Wazuh Manager trigger Active Response: custom-ddos-mitigation.py
          ↓
8. Script Python eksekusi: iptables -I INPUT -s 20.6.131.76 -j DROP
          ↓
9. IP attacker ter-block → ApacheBench timeout
          ↓
10. Setelah 600 detik → IP di-unblock otomatis (timeout Active Response)
```

---

## 8. Kesimpulan

Implementasi SOAR pada framework Wazuh SIEM berhasil mengotomatisasi proses deteksi dan mitigasi serangan HTTP Flood DDoS. Dengan menambahkan fitur Active Response melalui script Python `custom-ddos-mitigation.py`, sistem dapat:

1. **Mendeteksi** serangan DDoS secara real-time melalui Rule 100100
2. **Merespons otomatis** dalam hitungan detik tanpa intervensi admin
3. **Memblokir** IP attacker menggunakan `iptables` secara programatik
4. **Meng-unblock** IP secara otomatis setelah timeout 600 detik
5. **Mencatat** seluruh aktivitas SOAR di `custom-soar.log` untuk audit trail

Dibandingkan dengan implementasi SIEM sebelumnya yang memerlukan mitigasi manual, penambahan SOAR secara signifikan mengurangi waktu respons dari menit menjadi detik.

---
