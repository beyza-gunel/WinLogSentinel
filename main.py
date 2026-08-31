import sys
import csv
import json
import subprocess
import pandas as pd
import openpyxl
import os
import requests
import ipaddress
import hashlib
import Evtx.Evtx as evtx
from datetime import datetime, timedelta
from collections import deque

import xml.etree.ElementTree as ET

from PySide6.QtCore import QTimer, Signal, QThread, QFileInfo
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QPushButton, QVBoxLayout,
    QHBoxLayout, QGridLayout, QWidget, QTableWidget, QTableWidgetItem,
    QFileDialog, QLabel, QGroupBox, QMessageBox, QAbstractItemView,
    QComboBox, QLineEdit, QInputDialog, QDialog, QListWidget,
    QDialogButtonBox
)
from PySide6.QtGui import QColor, QFont

EVENT_TYPE_MAP = {
    "4624": "Successful Logon",
    "4625": "Failed Logon",
    "4634": "Logoff",
    "4648": "Explicit Credential Logon",
    "4672": "Special Privilege",
    "4688": "Process Creation",
    "4720": "Account Creation",
    "4722": "Account Enabled",
    "4724": "Password Reset",
    "4732": "Group Membership Change",
    "4740": "Account Lockout",
    "1102": "Audit Log Cleared",
    "5379": "Credential Access"
}

class TimelineDialog(QDialog):

    def __init__(self, events, parent=None):
        super().__init__(parent)

        self.setWindowTitle("🕒 Olay Zaman Çizelgesi")
        self.resize(800, 600)

        layout = QVBoxLayout(self)

        self.list_widget = QListWidget()
        layout.addWidget(self.list_widget)

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Close
        )

        buttons.rejected.connect(self.reject)

        layout.addWidget(buttons)

        sorted_events = sorted(
            events,
            key=lambda x: x.get("datetime")
            if x.get("datetime")
            else datetime.min
        )

        for event in sorted_events:

            detection = event.get(
                "detection",
                "Normal Aktivite"
            )

            text = (
                f"{event.get('date', '-')} "
                f"{event.get('time', '-')}  |  "
                f"Event {event.get('event_id', '-')}  |  "
                f"{event.get('user', '-')}  |  "
                f"{event.get('ip', '-')}  |  "
                f"{event.get('risk', '-')}  |  "
                f"{detection}"
            )

            self.list_widget.addItem(text)
        
class ClickableLabel(QLabel):
    clicked = Signal()
    def mousePressEvent(self, event):
        self.clicked.emit()
        super().mousePressEvent(event)

class DetectionEngine:

    def __init__(self):
        self.failed_attempts = {}
        self.login_history = {}

    def analyze(self, event):
        detections = []
        score = 0

        event_id = str(event.get("event_id", ""))
        user = event.get("user", "-")
        ip = event.get("ip", "-")
        process = event.get("process", "-")
        event_time = event.get("datetime")

        # =====================================================
        # RULE 1 - BRUTE FORCE
        # =====================================================

        if event_id == "4625":

            key = (user, ip)

            if key not in self.failed_attempts:
                self.failed_attempts[key] = []

            if event_time:
                self.failed_attempts[key].append(event_time)

                threshold = event_time - timedelta(minutes=5)

                self.failed_attempts[key] = [
                    t for t in self.failed_attempts[key]
                    if t >= threshold
                ]

                count = len(self.failed_attempts[key])

                if count >= 10:
                    detections.append(
                        f"Rule 1: Possible Brute Force ({count} attempts)"
                    )
                    score += 20

                elif count >= 3:
                    detections.append(
                        f"Rule 2: Multiple Failed Login ({count} attempts)"
                    )
                    score += 5

                else:
                    detections.append(
                        f"Failed Login ({count}. attempt)"
                    )
                    score += 1

        # =====================================================
        # RULE 3 - SUSPICIOUS ADMIN
        # =====================================================

        if event_id == "4672":
            detections.append(
                "Rule 3: Suspicious Admin Privilege Activity"
            )
            score += 5

        # =====================================================
        # RULE 4 - SUSPICIOUS PROCESS
        # =====================================================

        suspicious_processes = {
            "cmd.exe",
            "powershell.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe"
        }

        process_name = os.path.basename(process).lower()

        if event_id == "4688" and process_name in suspicious_processes:

            detections.append(
                f"Rule 4: Suspicious Process ({process_name})"
            )

            score += 10

        # =====================================================
        # RULE 5 - UNUSUAL LOGIN
        # =====================================================

        if event_id == "4624" and event_time:

            hour = event_time.hour

            if hour < 6 or hour >= 20:

                detections.append(
                    "Rule 5: Unusual Login Time"
                )

                score += 5

        return detections, score   

class RiskEngine:

    @staticmethod
    def calculate(score):

        if score <= 4:
            return "🟢 Low"

        elif score <= 9:
            return "🟡 Medium"

        elif score <= 19:
            return "🟠 High"

        elif score <= 49:
            return "🔴 Critical"

        return "☠️ Fatal"
         

class FirewallWorker(QThread):
    # Ana thread'e bilgi gönderecek sinyaller
    success_signal = Signal(str)
    already_blocked_signal = Signal(str) # 🚀 Zaten var olanlar için özel sinyal
    error_signal = Signal(str, str)

    def __init__(self, ip_address, parent=None):
        super().__init__(parent)
        self.ip_address = ip_address

    def run(self):
        try:
            ipaddress.ip_address(self.ip_address)
        except ValueError:
            return  # Geçersiz IP

        rule_name = f"WinLogSentinel_Block_{self.ip_address}"
        kontrol_komutu = ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"]
        
        # Kural zaten varsa ayrı sinyal gönderip çıkıyoruz
        if subprocess.run(kontrol_komutu, capture_output=True).returncode == 0:
            self.already_blocked_signal.emit(self.ip_address) # 🚀 Doğru değişken adı ve yeni sinyal
            return

        komut = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=block", f"remoteip={self.ip_address}"]
        
        try:
            subprocess.run(komut, check=True, capture_output=True)
            self.success_signal.emit(self.ip_address)  # Yeni engellendiğinde tetiklenir
        except subprocess.CalledProcessError as e:
            self.error_signal.emit(self.ip_address, str(e))

class LogWorker(QThread):
    
    security_last_id_updated = Signal(int)
    log_ready = Signal(dict, int)
    logs_batch_ready = Signal(list)
    analysis_finished = Signal(int)
    error = Signal(str)
    position_updated = Signal(int) # 🚀 Yeni imleç konumunu ana sınıfa bildirmek için eklenen sinyal

    def create_event(
        self,
        tarih,
        saat,
        event_id,
        kullanici,
        ip,
        hostname,
        process,
        event_type,
        source,
        durum,
        record_id
    ):
        try:
            event_datetime = datetime.strptime(
                f"{tarih} {saat}",
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            event_datetime = None

        return {
            "date": tarih,
            "time": saat,
            "datetime": event_datetime,
            "event_id": str(event_id),
            "user": kullanici,
            "ip": ip,
            "hostname": hostname,
            "process": process,
            "event_type": event_type,
            "source": source,
            "status": durum,
            "record_id": str(record_id),
            "detection": "",
            "detections": [],
            "score": 0,
            "risk": "🟢 Low",
            "recommended_action": ""
        }

    def __init__(self, file_path, ioc_mode, known_malicious_ips, scan_mode="gecmis_evtx", last_seen_record_id=0, test_ips=None):
        super().__init__()
        self.file_path = file_path
        self.ioc_mode = ioc_mode
        self.known_malicious_ips = known_malicious_ips
        self.scan_mode = scan_mode
        self.last_seen_record_id = last_seen_record_id
        # Doğrudan içeride güvenle tanımlıyoruz (gelmezse boş set yap)
        self.test_ips = test_ips if test_ips is not None else set()

    def run(self):
        try:
            total_records_processed = 0
            
            if self.scan_mode == "live_security":
                total_records_processed = self.parse_wevtutil_live()
                
            elif self.scan_mode == "live_file":
                if not self.file_path or not os.path.exists(self.file_path):
                    return 0
                
                current_position = self.last_seen_record_id
                new_rows = []
                
                with open(self.file_path, "rb") as file:
                    file_size = os.path.getsize(self.file_path)
                    
                    if current_position > file_size:
                        current_position = 0
                        self.last_seen_record_id = 0
                        
                    file.seek(current_position)
                    
                    valid_lines = []
                    while True:
                        if self.isInterruptionRequested():
                            break
                            
                        line_bytes = file.readline()
                        if not line_bytes:
                            break
                            
                        if not line_bytes.endswith(b'\n'):
                            break
                            
                        line_str = line_bytes.decode("utf-8-sig", errors="ignore")
                        valid_lines.append(line_str)
                        current_position = file.tell()
                        
                if valid_lines:
                    for parts in csv.reader(valid_lines):
                        if self.isInterruptionRequested():
                            break
                        
                        parts = [p.strip() for p in parts]

                        if len(parts) > 2 and parts[2].lower() in ("event id", "eventid"):
                            continue

                        if len(parts) >= 6:
                            new_rows.append(parts)
                
                total_records_processed = len(new_rows)
                
                for idx, row in enumerate(new_rows):
                    if self.isInterruptionRequested():
                        break
                    
                    ip = row[4] if len(row) > 4 else "-"
                    
                    tespit_nedeni = ""
                    if ip and ip != "-":
                        if getattr(self, 'ioc_mode', '') == "VirusTotal Canlı Sorgu (Online)":
                            vt_result = self.check_virustotal(ip)
                            if vt_result == "malicious":
                                tespit_nedeni = "🚨 VT DETECTED (VirusTotal Zararlı Tespiti)"
                            elif vt_result == "unknown":
                                tespit_nedeni = "⚠️ VT BİLİNMİYOR (Sorgu Başarısız/Kota Doldu)"
                        else:
                            if hasattr(self, 'known_malicious_ips') and ip in self.known_malicious_ips:
                                tespit_nedeni = "🚨 IOC MATCH DETECTED (Zararlı IP Tespiti)"
                            elif hasattr(self, 'test_ips') and ip in self.test_ips:
                                tespit_nedeni = "🧪 TEST IP ALGILANDI (Simülasyon)"
                    
                    try:
                        dt_obj = datetime.strptime(f"{row[0]} {row[1]}", "%Y-%m-%d %H:%M:%S")
                    except:
                        dt_obj = None

                    # 🚀 LİSTE DEĞİL, ARTIK KUSURSUZ BİR SÖZLÜK (EVENT) GÖNDERİYORUZ!
                    event = {
                        "date": row[0],
                        "time": row[1],
                        "event_id": str(row[2]),
                        "user": row[3] if len(row) > 3 else "-",
                        "ip": ip,
                        "hostname": "-",
                        "process": row[5] if len(row) > 5 else "-",
                        "event_type": EVENT_TYPE_MAP.get(str(row[2]), "Other"),
                        "source": "CSV",
                        "status": row[5] if len(row) > 5 else "-",
                        "record_id": f"{current_position}_{idx}",
                        "datetime": dt_obj,
                        "detection": tespit_nedeni,
                        "detections": [tespit_nedeni] if tespit_nedeni else [],
                        "score": 0,
                        "risk": "🟢 Low",
                        "recommended_action": ""
                    }
                    self.log_ready.emit(event, idx)

                self.position_updated.emit(current_position)
                
            elif self.scan_mode == "csv":
                # 🚀 STATİK CSV DOSYASINI TEK SEFERDE OKUMA MODU
                if not self.file_path or not os.path.exists(self.file_path):
                    return
                    
                with open(self.file_path, "r", encoding="utf-8-sig", errors="ignore") as file:
                    for idx, parts in enumerate(csv.reader(file)):
                        if self.isInterruptionRequested():
                            break
                        
                        parts = [p.strip() for p in parts]

                        if idx == 0 and len(parts) > 2:
                            if parts[2].strip().lower() in ("event id", "eventid"):
                                continue

                        if len(parts) >= 6:
                            ip = parts[4] if len(parts) > 4 else "-"
                            tespit_nedeni = ""
                            if ip and ip != "-":
                                if getattr(self, 'ioc_mode', '') == "VirusTotal Canlı Sorgu (Online)":
                                    vt_result = self.check_virustotal(ip)
                                    if vt_result == "malicious":
                                        tespit_nedeni = "🚨 VT DETECTED (VirusTotal Zararlı Tespiti)"
                                    elif vt_result == "unknown":
                                        tespit_nedeni = "⚠️ VT BİLİNMİYOR (Sorgu Başarısız/Kota Doldu)"
                                else:
                                    if hasattr(self, 'known_malicious_ips') and ip in self.known_malicious_ips:
                                        tespit_nedeni = "🚨 IOC MATCH DETECTED (Zararlı IP Tespiti)"
                                    elif hasattr(self, 'test_ips') and ip in self.test_ips:
                                        tespit_nedeni = "🧪 TEST IP ALGILANDI (Simülasyon)"
                            
                            try:
                                dt_obj = datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
                            except:
                                dt_obj = None

                            # 🚀 Sözlük (Dictionary) Modeli
                            event = {
                                "date": parts[0],
                                "time": parts[1],
                                "event_id": str(parts[2]),
                                "user": parts[3] if len(parts) > 3 else "-",
                                "ip": ip,
                                "hostname": "-",
                                "process": parts[5] if len(parts) > 5 else "-",
                                "event_type": EVENT_TYPE_MAP.get(str(parts[2]), "Other"),
                                "source": "CSV",
                                "status": parts[5] if len(parts) > 5 else "-",
                                "record_id": str(idx),
                                "datetime": dt_obj,
                                "detection": tespit_nedeni,
                                "detections": [tespit_nedeni] if tespit_nedeni else [],
                                "score": 0,
                                "risk": "🟢 Low",
                                "recommended_action": ""
                            }
                            self.log_ready.emit(event, idx)
                            total_records_processed += 1

            else:    
                temp_path = self.file_path
                    
                with evtx.Evtx(temp_path) as evtx_file:
                    ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
                    
                    total_records_processed = 0
                    gecici_batch = []
                    
                    for idx, record in enumerate(evtx_file.records()):
                        if self.isInterruptionRequested(): 
                            break
                            
                        total_records_processed = idx + 1
                        
                        try:
                            root = ET.fromstring(record.xml())
                            system = root.find(f'{ns}System')
                            event_data = root.find(f'{ns}EventData')
                            if system is None: continue
                            
                            event_id = system.find(f'{ns}EventID').text if system.find(f'{ns}EventID') is not None else ""
                            
                            provider = system.find(f'{ns}Provider')
                            source = "-"
                            if provider is not None:
                                source = provider.get("Name", "-")

                            event_type = EVENT_TYPE_MAP.get(str(event_id), "Other")

                            raw_time = system.find(f'{ns}TimeCreated').get('SystemTime') if system.find(f'{ns}TimeCreated') is not None else ""
                            record_id_el = system.find(f'{ns}EventRecordID')
                            event_record_id = record_id_el.text if record_id_el is not None else str(idx)
                            
                            tarih, saat = "-", "-"
                            if raw_time:
                                dt_local = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone()
                                t_str, s_str = dt_local.strftime("%Y-%m-%d"), dt_local.strftime("%H:%M:%S")
                            else:
                                t_str, s_str = "-", "-"
                                
                            kullanici = "System"
                            ip = "-"
                            hostname = "-"
                            process = "-"
                            durum = "Bilgi"

                            if event_data is not None:
                                for data in event_data.findall(f'{ns}Data'):
                                    name = data.get("Name")
                                    val = data.text or ""

                                    if name in ["TargetUserName", "SubjectUserName"]:
                                        if val and val != "SYSTEM":
                                            kullanici = val
                                    elif name in ["IpAddress", "SourceNetworkAddress"]:
                                        if val and val != "-":
                                            ip = val
                                    elif name in ["WorkstationName"]:
                                        if val and val != "-":
                                            hostname = val
                                    elif name == "NewProcessName":
                                        if val:
                                            process = val

                            tespit_nedeni = ""
                            if ip and ip != "-":
                                if self.isInterruptionRequested():
                                    break
                                if getattr(self, 'ioc_mode', '') == "VirusTotal Canlı Sorgu (Online)":
                                    vt_result = self.check_virustotal(ip)
                                    if vt_result == "malicious":
                                        tespit_nedeni = "🚨 VT DETECTED (VirusTotal Zararlı Tespiti)"
                                    elif vt_result == "unknown":
                                        tespit_nedeni = "⚠️ VT BİLİNMİYOR (Sorgu Başarısız/Kota Doldu)"
                                else:
                                    if hasattr(self, 'known_malicious_ips') and ip in self.known_malicious_ips:
                                        tespit_nedeni = "🚨 IOC MATCH DETECTED (Zararlı IP Tespiti)"
                                    elif hasattr(self, 'test_ips') and ip in self.test_ips:
                                        tespit_nedeni = "🧪 TEST IP ALGILANDI (Simülasyon)"
                            
                            try:
                                dt_obj = datetime.strptime(f"{t_str} {s_str}", "%Y-%m-%d %H:%M:%S")
                            except:
                                dt_obj = None

                            # 🚀 STATİK EVTX İÇİN KUSURSUZ SÖZLÜK MODELİ
                            event = {
                                "date": t_str,
                                "time": s_str,
                                "event_id": str(event_id),
                                "user": kullanici,
                                "ip": ip,
                                "hostname": hostname,
                                "process": process,
                                "event_type": event_type,
                                "source": source,
                                "status": durum,
                                "record_id": str(event_record_id),
                                "datetime": dt_obj,
                                "detection": tespit_nedeni,
                                "detections": [tespit_nedeni] if tespit_nedeni else [],
                                "score": 0,
                                "risk": "🟢 Low",
                                "recommended_action": ""
                            }
                            
                            self.log_ready.emit(event, idx)
                            gecici_batch.append(event)
                            
                            if len(gecici_batch) >= 200:
                                self.logs_batch_ready.emit(gecici_batch)
                                gecici_batch = []
                                self.msleep(10)
                                
                        except Exception:
                            continue
                            
                    if gecici_batch:
                        self.logs_batch_ready.emit(gecici_batch)
                        
            
            self.analysis_finished.emit(total_records_processed)
            
        except Exception as e:
            self.error.emit(str(e))

    def check_virustotal(self, ip):
        # 1. Önbellek (Cache) yoksa otomatik oluştur
        if not hasattr(self, 'vt_cache'):
            self.vt_cache = {}

        # 2. IP Doğrulama ve Yerel/Özel Ağ Kontrolü (is_private ile kusursuz filtreleme)
        if not ip or ip == "-":
            return "clean"  # Geçersiz IP'ler zararlı değildir, temiz kabul edip atlıyoruz
            
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                self.vt_cache[ip] = "clean" # Yerel ağ IP'lerini temiz kabul et
                return "clean"
        except ValueError:
            self.vt_cache[ip] = "clean"
            return "clean"

        # 3. Bu IP daha önce sorgulandıysa, VT'ye gitmeden direkt hafızadaki sonucu dön
        if ip in self.vt_cache:
            return self.vt_cache[ip]

        # 4. Güvenli VT API v3 Sorgusu (Environment Variable'dan okur)
        api_key = os.getenv("VT_API_KEY") 
        
        if not api_key:
            print("Uyarı: Sistemde VT_API_KEY tanımlı değil!")
            return "unknown"  # API Key yoksa temiz diyemeyiz, "bilinmiyor"

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"accept": "application/json", "x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers, timeout=2.0)
            
            # 🚀 RATE LIMIT (KOTA) KONTROLÜ
            if response.status_code == 429:
                print(f"⚠️ VT API Limitine (429) takıldık! IP: {ip} atlanıyor.")
                # DİKKAT: Cache'e yazmıyoruz, sadece değeri döndürüyoruz
                return "unknown"
                
            if response.status_code == 200:
                data = response.json()
                malicious_count = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0)
                
                # 🚀 KESİN SONUÇ
                is_malicious = "malicious" if malicious_count > 0 else "clean"
                self.vt_cache[ip] = is_malicious  # SADECE BURADA CACHE'E YAZIYORUZ
                return is_malicious
            else:
                print(f"VT API Hatası: {ip} sorgulanamadı. Status Code: {response.status_code}")
                # DİKKAT: Cache'e yazmıyoruz
                return "unknown"
                
        except Exception as e:
            print(f"VT Kod Hatası: {e}")
            # DİKKAT: Cache'e yazmıyoruz (İnternet kopması geçicidir)
            return "unknown"

    def parse_wevtutil_live(self):
        logs_count = 0
        try:
            # 🚀 Karmaşık XML sorguları yerine en kararlı çalışan komutu kullanıyoruz
            cmd = ["wevtutil", "qe", "Security", "/rd:true", "/f:xml", "/c:100"]
            
            result = subprocess.run(cmd, shell=False, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if result.returncode != 0:
                result = subprocess.run(cmd, shell=False, capture_output=True, text=True, encoding='cp1254', errors='ignore')

            if result.returncode != 0 or not result.stdout.strip():
                return 0

            xml_output = f"<Events>{result.stdout}</Events>"
            root = ET.fromstring(xml_output)
            ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
            
            records = root.findall(f'.//{ns}Event')
            logs_count = len(records)
            
            try:
                safe_last_id = int(getattr(self, 'last_seen_record_id', 0))
            except (TypeError, ValueError):
                safe_last_id = 0

            gecici_liste = []
            for event in records:
                if self.isInterruptionRequested(): 
                    break

                try:
                    system = event.find(f'{ns}System')
                    event_data = event.find(f'{ns}EventData')
                    if system is None: continue
                    
                    event_id = system.find(f'{ns}EventID').text if system.find(f'{ns}EventID') is not None else ""

                    provider = system.find(f'{ns}Provider')
                    source = "-"
                    if provider is not None:
                        source = provider.get("Name", "-")

                    event_type = EVENT_TYPE_MAP.get(str(event_id), "Other")
                    raw_time = system.find(f'{ns}TimeCreated').get('SystemTime') if system.find(f'{ns}TimeCreated') is not None else ""
                    
                    record_id_el = system.find(f'{ns}EventRecordID')
                    event_record_id = record_id_el.text if record_id_el is not None else "0"
                    
                    # 🚀 Python tarafında ID filtresi (Wevtutil hata 6'yı tamamen tarihe gömer)
                    if safe_last_id > 0 and str(event_record_id).isdigit():
                        if int(event_record_id) <= safe_last_id:
                            continue

                    siralama_zamani = raw_time if raw_time else "0000"
                    tarih, saat = "-", "-"
                    if raw_time:
                        dt_local = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone()
                        tarih, saat = dt_local.strftime("%Y-%m-%d"), dt_local.strftime("%H:%M:%S")
                        
                    kullanici = "System"
                    ip = "-"
                    hostname = "-"
                    process = "-"
                    durum = "Bilgi"

                    if event_data is not None:
                        for data in event_data.findall(f'{ns}Data'):
                            name = data.get("Name")
                            val = data.text or ""

                            if name in ["TargetUserName", "SubjectUserName"]:
                                if val and val != "SYSTEM":
                                    kullanici = val
                            elif name in ["IpAddress", "SourceNetworkAddress"]:
                                if val and val != "-":
                                    ip = val
                            elif name in ["WorkstationName"]:
                                if val and val != "-":
                                    hostname = val
                            elif name == "NewProcessName":
                                if val:
                                    process = val
                    
                    tespit_nedeni = ""
                    if ip and ip != "-":
                        if getattr(self, 'ioc_mode', '') == "VirusTotal Canlı Sorgu (Online)":
                            vt_result = self.check_virustotal(ip)
                            if vt_result == "malicious":
                                tespit_nedeni = "🚨 VT DETECTED (VirusTotal Zararlı Tespiti)"
                            elif vt_result == "unknown":
                                tespit_nedeni = "⚠️ VT BİLİNMİYOR (Sorgu Başarısız/Kota Doldu)"
                        else:
                            if hasattr(self, 'known_malicious_ips') and ip in self.known_malicious_ips:
                                tespit_nedeni = "🚨 IOC MATCH DETECTED (Zararlı IP Tespiti)"
                            elif hasattr(self, 'test_ips') and ip in self.test_ips:
                                tespit_nedeni = "🧪 TEST IP ALGILANDI (Simülasyon)"

                    try:
                        dt_obj = datetime.strptime(f"{tarih} {saat}", "%Y-%m-%d %H:%M:%S")
                    except:
                        dt_obj = None

                    event_dict = {
                        "date": tarih,
                        "time": saat,
                        "event_id": str(event_id),
                        "user": kullanici,
                        "ip": ip,
                        "hostname": hostname,
                        "process": process,
                        "event_type": event_type,
                        "source": source,
                        "status": durum,
                        "record_id": str(event_record_id),
                        "datetime": dt_obj,
                        "detection": tespit_nedeni,
                        "detections": [tespit_nedeni] if tespit_nedeni else [],
                        "score": 0,
                        "risk": "🟢 Low",
                        "recommended_action": ""
                    }
                    gecici_liste.append((siralama_zamani, event_dict))
                except Exception:
                    continue
            
            gecici_liste.sort(key=lambda x: x[0], reverse=False)

            max_id_seen = safe_last_id
            for idx, item in enumerate(gecici_liste):
                if self.isInterruptionRequested():
                    break
                
                self.log_ready.emit(item[1], idx)
                rec_id = item[1].get("record_id", "0")
                if str(rec_id).isdigit():
                    max_id_seen = max(max_id_seen, int(rec_id))

            if max_id_seen > safe_last_id:
                self.last_seen_record_id = max_id_seen
                if hasattr(self, 'security_last_id_updated'):
                    self.security_last_id_updated.emit(self.last_seen_record_id)

        except Exception as e:
            print(f"Wevtutil genel hata: {e}")

        return logs_count
    
class MainWindow(QMainWindow):

    def detect_account_compromise(self):

        if len(self.analyzed_events) < 4:
            return None

        recent = self.analyzed_events[-20:]

        failed = [
            e for e in recent
            if e.get("event_id") == "4625"
        ]

        successful = [
            e for e in recent
            if e.get("event_id") == "4624"
        ]

        privileges = [
            e for e in recent
            if e.get("event_id") == "4672"
        ]

        processes = [
            e for e in recent
            if e.get("event_id") == "4688"
        ]

        if (
            len(failed) >= 3
            and successful
            and (privileges or processes)
        ):

            user = successful[-1].get("user", "-")
            ip = successful[-1].get("ip", "-")

            return {
                "name": "Possible Account Compromise",
                "user": user,
                "ip": ip,
                "failed_count": len(failed),
                "risk": "☠️ Fatal"
            }

        return None

    def calculate_file_hash(self, file_path):
        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                for chunk in iter(
                    lambda: f.read(1024 * 1024),
                    b""
                ):
                    sha256.update(chunk)

            return sha256.hexdigest()

        except Exception:
            return "-"

    def get_recommended_action(self, event):

        detection = event.get("detection", "")
        risk = event.get("risk", "")
        event_id = str(event.get("event_id", ""))

        if "Brute Force" in detection:

            return (
                "Aynı kaynak IP ve kullanıcı için başarısız "
                "girişler incelenmeli; gerekirse IP engellenmelidir."
            )

        if "Multiple Failed Login" in detection:

            return (
                "Kullanıcı hesabı ve kaynak IP adresi "
                "güvenlik açısından incelenmelidir."
            )

        if "Suspicious Admin" in detection:

            return (
                "Yönetici yetkisinin gerekliliği ve ilgili "
                "hesap aktivitesinin doğrulanması önerilir."
            )

        if "Suspicious Process" in detection:

            return (
                "Oluşturulan process'in komut satırı, kullanıcı "
                "bağlamı ve parent process bilgilerinin incelenmesi önerilir."
            )

        if "Unusual Login" in detection:

            return (
                "Oturum açma zamanı ve ilgili kullanıcı aktivitesi "
                "ile kaynak IP'nin doğrulanması önerilir."
            )

        if "IOC MATCH" in detection:

            return (
                "IOC eşleşmesinin doğrulanması ve ilgili IP'nin "
                "güvenlik açısından incelenmesi önerilir."
            )

        if "VT DETECTED" in detection:

            return (
                "VirusTotal tarafından şüpheli olarak işaretlenen "
                "IP adresinin güvenlik açısından incelenmesi önerilir."
            )

        if "Critical" in risk or "Fatal" in risk:

            return (
                "Olayın ilgili sistem kayıtları ve kullanıcı "
                "aktivitesiyle birlikte ayrıntılı olarak incelenmesi önerilir."
            )

        return "Normal aktivite için ek işlem gerekmemektedir."

    def stop_worker_safely(self, worker):
        if worker is not None and worker.isRunning():
            worker.requestInterruption()
            worker.wait(3000)

    def add_log_rows_batch(self, logs):
        if not logs:
            return

        self._batch_update = True
        self.log_table.setUpdatesEnabled(False)

        try:
            for idx, log in enumerate(logs):
                self.add_single_log_row_live(
                    log,
                    idx,
                    insert_row=True
                )

            # Tablo aşırı büyümesin
            MAX_TABLE_ROWS = 10000

            while self.log_table.rowCount() > MAX_TABLE_ROWS:
                self.log_table.removeRow(0)

        finally:
            self._batch_update = False
            self.log_table.setUpdatesEnabled(True)

        self.update_dashboard()

        self.log_table.viewport().update()
        scrollbar = self.log_table.verticalScrollBar()
        if scrollbar:
            scrollbar.rangeChanged.connect(lambda min_val, max_val: scrollbar.setValue(max_val))
            scrollbar.setValue(scrollbar.maximum())

        QApplication.processEvents()

    def update_security_last_id(self, last_id):
        """Windows Security canlı izlemede son taranan record ID'yi günceller."""
        try:
            self.last_seen_record_id = int(last_id)
        except (TypeError, ValueError):
            pass

    def block_ip_in_firewall(self, ip_address):
        """Windows Güvenlik Duvarı'na seçilen IP adresini engellemek için kural ekler."""
        if not ip_address or ip_address == "-" or ip_address.startswith("🧪") or ip_address.startswith("🚨"):
            # Geçersiz veya IP formatında olmayan stringleri engellemeye çalışmama koruması
            return False

        rule_name = f"WinLogSentinel_Block_{ip_address}"
        try:
            # Yönetici yetkisi gerektiren netsh komutu ile gelen/giden (inbound/outbound) engelleme kuralı
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                "dir=in",
                "action=block",
                f"remoteip={ip_address}"
            ]
            
            # Komutu çalıştır (Windows'ta arka planda yönetici izni isteyebilir)
            result = subprocess.run(cmd, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            
            if result.returncode == 0:
                # İkinci bir kural olarak outbound da eklenebilir veya inbound yeterli olabilir
                return True
            else:
                # Yetki reddedildiyse veya hata aldıysa
                print(f"Firewall kuralı eklenemedi: {result.stderr}")
                return False
        except Exception as e:
            print(f"Firewall hata: {str(e)}")
            return False

    def add_audit_log(self, message):
        """Sistemde gerçekleşen tüm güvenlik işlemlerini tarih ve saat damgasıyla denetim kaydına yazar."""
        try:
            BASE_DIR = os.path.dirname(os.path.abspath(__file__))
            audit_path = os.path.join(BASE_DIR, "denetim_kaydi.txt")
            
            zaman = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(audit_path, "a", encoding="utf-8") as f:
                f.write(f"[{zaman}] {message}\n")
        except Exception as e:
            print(f"Denetim kaydı yazılamadı: {e}")

    def add_event_to_table(self, event, insert_row=True, target_row=None):
        if insert_row or target_row is None:
            target_row = self.log_table.rowCount()
            self.log_table.insertRow(target_row)

        risk = event.get("risk", "🟢 Low")

        # Renkler
        if "Low" in risk:
            renk = QColor(100, 255, 100); yazi_rengi = QColor(0, 0, 0)
        elif "Medium" in risk:
            renk = QColor(255, 255, 100); yazi_rengi = QColor(0, 0, 0)
        elif "High" in risk:
            renk = QColor(255, 165, 0); yazi_rengi = QColor(0, 0, 0)
        elif "Critical" in risk:
            renk = QColor(255, 50, 50); yazi_rengi = QColor(255, 255, 255)
        elif "Fatal" in risk:
            renk = QColor(0, 0, 0); yazi_rengi = QColor(255, 255, 255)
        else:
            renk = QColor(255, 255, 255); yazi_rengi = QColor(0, 0, 0)

        # 🚀 Sütun sıralaması ile 100% uyumlu liste:
        values = [
            event.get("date", "-"),                          # 0: Tarih
            event.get("time", "-"),                          # 1: Saat
            event.get("display_event", event.get("event_id", "-")), # 2: Event ID (Açıklamalı)
            event.get("user", "-"),                          # 3: Kullanıcı
            event.get("ip", "-"),                            # 4: IP Adresi
            event.get("status", "-"),                        # 5: Durum
            event.get("source", "-"),                        # 6: Kaynak (Source)
            event.get("event_type", "-"),                    # 7: Olay Tipi (Event Type)
            risk,                                            # 8: Risk Seviyesi
            event.get("detection") or "Normal Aktivite"      # 9: Tespit Nedeni
        ]

        kalin_yazi = ("Critical" in risk or "Fatal" in risk)

        for col, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            item.setBackground(renk)
            item.setForeground(yazi_rengi)
            if kalin_yazi:
                kalin_font = QFont(); kalin_font.setBold(True); item.setFont(kalin_font)
            self.log_table.setItem(target_row, col, item)

    def add_single_log_row_live(self, event, row_idx, insert_row=True, target_row=None):
        """Worker'dan gelen veriyi karşılayan ana kontrolcü."""
        # 🛡️ Eğer gelen veri sözlük değilse (liste geldiyse) Shiboken hatasını önlemek için güvenle dön
        if isinstance(event, list):
            # Eğer eski tip listeden gelen sistem mesajı değilse dön
            if len(event) >= 3 and not any(k in str(event[2]) for k in ["🟢", "⏳", "HATA"]):
                return
            
        # 1️⃣ Sistem Mesajları Koruması (Yeşil bilgi satırları için)
        if isinstance(event, list) and len(event) >= 3:
            event_id_str = str(event[2])
            if "🟢 CANLI" in event_id_str or "⏳ BİLGİ" in event_id_str or "HATA" in event_id_str:
                target_row = self.log_table.rowCount()
                self.log_table.insertRow(target_row)
                for col_idx in range(min(len(event), self.log_table.columnCount())):
                    hucre = QTableWidgetItem(str(event[col_idx]))
                    hucre.setBackground(QColor(0, 80, 0))
                    hucre.setForeground(QColor(255, 255, 255))
                    font = QFont(); font.setBold(True); hucre.setFont(font)
                    self.log_table.setItem(target_row, col_idx, hucre)
                self.log_table.scrollToBottom()
                return

        if not isinstance(event, dict): return
        
        # 2️⃣ Kesin Tekilleştirme
        log_id = str(event.get("record_id", ""))
        if log_id in self.seen_logs_set:
            return
            
        if len(self.seen_logs_deque) >= self.seen_logs_deque.maxlen:
            oldest_id = self.seen_logs_deque[0]
            self.seen_logs_set.discard(oldest_id)

        self.seen_logs_deque.append(log_id)
        self.seen_logs_set.add(log_id) 

        # 3️⃣ Risk Motoru (Risk Engine)
        if not hasattr(self, 'failed_attempts'): self.failed_attempts = {}
        
        event_id = event.get("event_id", "")
        kullanici = event.get("user", "-")
        ip = event.get("ip", "-")
        durum = event.get("status", "-")
        
        if str(event_id) == "4624": 
            self.failed_attempts[(kullanici, ip)] = []

        # 🚀 Skoru her satır için sıfırdan başlatıyoruz (birikmeyi önler)
        risk_skoru = 0  
        tespitler = []

        # Dış İstihbarat (VT veya IOC)
        vt_tespit = event.get("detection", "")
        if vt_tespit:
            tespitler.append(vt_tespit)
            if "DETECTED" in vt_tespit or "MATCH" in vt_tespit:
                risk_skoru += 100 
            elif "BİLİNMİYOR" in vt_tespit:
                risk_skoru += 5   

        # İç Kurallar
        if "Administrator" in kullanici and str(event_id) == "4672":
            risk_skoru += 5
            tespitler.append("Kural 3: Şüpheli Yönetici Yetkisi Ataması")
        elif str(event_id) == "4688" and "cmd.exe" in durum:
            risk_skoru += 16
            tespitler.append("Kural 4: Şüpheli İşlem")
        elif str(event_id) == "4625":
            hedef = (kullanici, ip)
            if hedef not in self.failed_attempts:
                self.failed_attempts[hedef] = []
                
            log_zamani = event.get("datetime") or datetime.now()
            self.failed_attempts[hedef].append(log_zamani)
            zaman_siniri = log_zamani - timedelta(minutes=5)
            self.failed_attempts[hedef] = [z for z in self.failed_attempts[hedef] if z >= zaman_siniri]
            
            deneme_sayisi = len(self.failed_attempts[hedef])
            if deneme_sayisi >= 3:
                risk_skoru += 20
                tespitler.append(f"Kural 1: Brute Force İhtimali ({deneme_sayisi}. Deneme - Son 5 Dk)")
            else:
                risk_skoru += 1
                tespitler.append(f"Kural 2: Başarısız Giriş ({deneme_sayisi}. Deneme)")

        son_tespit = " | ".join(tespitler) if tespitler else ""
        event["detection"] = son_tespit
        event["score"] = risk_skoru

        # Türkçe Olay Açıklamaları
        event_sozlugu = {
            "4624": "Başarılı Oturum Açma", "4625": "Hatalı Şifre Denemesi", "4634": "Oturum Kapatıldı",
            "4647": "Kullanıcı Çıkış Yaptı", "4672": "Özel Yetki (Admin) Kullanıldı", "4688": "Yeni Program/Komut Çalıştırıldı",
            "4720": "Yeni Hesap Açıldı", "4722": "Hesap Aktif Hale Getirildi", "4724": "Şifre Sıfırlama İşlemi",
            "4732": "Gruba Yeni Üye Eklendi", "4740": "Hesap Kilitlendi", "1102": "DİKKAT: Loglar Silindi!",
            "5379": "Kayıtlı Şifrelere Erişildi"
        }
        aciklama = event_sozlugu.get(str(event_id), "Standart Sistem İşlemi")
        event["display_event"] = f"{event_id} ({aciklama})"

        # 🚀 Risk Seviyesi Eşikleri (Fatal sadece VirusTotal / IOC eşleşmelerine ayrıldı)
        if ("VT DETECTED" in son_tespit or "IOC MATCH" in son_tespit) and "TEST" not in son_tespit:
            risk_seviyesi = "☠️ Fatal"
            if ip and ip != "-" and ip not in getattr(self, 'whitelisted_ips', set()) and ip not in self.already_blocked_ips:
                self.already_blocked_ips.add(ip)
                fw_worker = FirewallWorker(ip, self)
                fw_worker.success_signal.connect(self.on_firewall_success)
                fw_worker.already_blocked_signal.connect(self.on_firewall_already_blocked) 
                fw_worker.error_signal.connect(self.on_firewall_error)
                self.active_firewall_workers.append(fw_worker)
                fw_worker.finished.connect(lambda w=fw_worker: self.active_firewall_workers.remove(w) if w in self.active_firewall_workers else None)
                fw_worker.start()
            self.current_fatal_alerts.append(f"⏱️ {event.get('time', '-')} | IP: {ip} - {son_tespit}")
        elif risk_skoru == 0:
            risk_seviyesi = "🟢 Low"
        elif 1 <= risk_skoru <= 9:
            risk_seviyesi = "🟡 Medium"
        elif 10 <= risk_skoru <= 19:
            risk_seviyesi = "🟠 High"
        else:
            risk_seviyesi = "🔴 Critical"  # Brute force maksimum Critical'da kalır, siyah olmasını engeller
            
        event["risk"] = risk_seviyesi
        event["recommended_action"] = self.get_recommended_action(event)

        # 4️⃣ Analyzed Events Veritabanına Ekle
        if not hasattr(self, 'analyzed_events'):
            self.analyzed_events = []
        self.analyzed_events.append(event)

        self.register_dashboard_stat(event_id, kullanici, ip, risk_seviyesi)

        # 5️⃣ Tabloyu Güncelle (View Fonksiyonunu Çağır)
        self.add_event_to_table(event, insert_row, target_row)

        if not getattr(self, '_batch_update', False):
            self.update_dashboard()
            if insert_row:
                # 🚀 Canlı loglar akarken tabloyu ve scrollbar'ı anında en alta sabitleyen kesin çözüm
                self.log_table.scrollToBottom()
                scrollbar = self.log_table.verticalScrollBar()
                if scrollbar:
                    scrollbar.setValue(scrollbar.maximum())

    def start_live_timer(self):
        """Sadece CSV dosyası canlı takibini başlatır."""
        if not self.timer.isActive():
            self.timer.start(3000)

    def toggle_security_live_mode(self):
        """Windows Security canlı izleme modunu ayrı bir butonla başlatır/durdurur."""
        # Eğer zaten canlı Windows Security modu çalışıyorsa durdur
        if getattr(self, 'is_security_live_active', False):
            if self.security_timer.isActive():
                self.security_timer.stop()

            self.is_security_live_active = False

            self.notifications_enabled = False
            self.status_queue.clear()

            self.btn_security_live.setText(
                "🛡️ Windows Security Canlı İzle"
            )

            self.btn_security_live.setStyleSheet("")

            self.add_audit_log(
                "Windows Security canlı izleme durduruldu."
            )

            return

        QApplication.processEvents()
        
        # 🚀 AKILLI TEMİZLİK: Eğer ekranda bir statik dosya (.evtx veya .csv) açıksa temizle.
        # Ama sadece canlı izleme duraklatılmışsa SİLME (eski canlı loglar ekranda kalsın).
        if getattr(self, 'current_file', None) is not None:
            self.log_table.setRowCount(0)
            self.seen_logs_deque.clear()
            self.seen_logs_set.clear()
            self.reset_dashboard_stats()
            self.failed_attempts = {}
            self.current_fatal_alerts = []
            self.current_file = None  # Artık dosya modunda değiliz

        # Eğer o sırada CSV canlı takibi çalışıyorsa çakışmaması için onu durdur
        if hasattr(self, 'timer') and self.timer.isActive():
            self.timer.stop()

        self.notifications_enabled = True
        self.status_queue.clear()
        
        # __init__ içinde zaten tanımlı olduğu için direkt başlatıyoruz
        self.security_timer.start(3000) 
        self.is_security_live_active = True
        
        self.btn_security_live.setText("⏹️ Windows Security İzlemeyi Durdur")
        self.btn_security_live.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold;")
        self.add_audit_log("Windows Security canlı izleme modu başlatıldı.")
        
        # Timer'ın 3 saniye beklemesini beklemeden ilk verileri hemen çekmesi için manuel tetikliyoruz
        self.run_live_update()

    def queue_status_message(self, message):
        """Bildirimleri yalnızca canlı izleme modunda kuyruğa ekler."""
    
        if not self.notifications_enabled:
            return

        if message not in self.status_queue:
            self.status_queue.append(message)

    def process_status_queue(self):
        if not self.notifications_enabled:
            self.status_queue.clear()
            return

        if self.status_queue:
            msg = self.status_queue.pop(0)
            self.statusBar().showMessage(msg, 2000)

    def __init__(self):

        self.risk_engine = RiskEngine()
        self.detection_engine = DetectionEngine()

        super().__init__()
        self.setWindowTitle("WinLogSentinel - Security Log Analyzer (Ultimate Edition)")
        self.resize(1100, 750) 
        
        ekran = QApplication.primaryScreen().availableGeometry()
        self.move((ekran.width() - self.width()) // 2, (ekran.height() - self.height()) // 2)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        self.dashboard_group = QGroupBox("📊 Güvenlik Dashboard (Detaylar için metinlere tıklayabilirsiniz)")
        dashboard_layout = QGridLayout() 

        self.last_seen_record_id = 0

        # Oturum durumu ve Worker takibi için başlangıç tanımlamaları
        self.session_blocked_ips = set()
        self.already_blocked_ips = set()
        self.active_firewall_workers = []
        self.current_fatal_alerts = []
        self.whitelisted_ips = set()

        self.timer = QTimer(self)  # Sadece CSV canlı takip için
        self.timer.timeout.connect(self.run_live_file_update)

        self.security_timer = QTimer(self)  # Sadece Windows Security için
        self.security_timer.timeout.connect(self.run_live_update)

        self.lbl_total = ClickableLabel("Toplam Olay: 0")
        self.lbl_critical = ClickableLabel("🔴 Kritik Olay: 0")
        self.lbl_suspicious = ClickableLabel("🚨 Şüpheli Olay: 0") # 🚀 YENİ EKLENDİ
        self.lbl_risk_dist = ClickableLabel("📊 Risk Dağılımı: 🟢 Low | 🟡 Medium | 🟠 High | 🔴 Critical | ☠️ Fatal")
        self.lbl_top_ip = ClickableLabel("🌐 En Aktif IP: -")
        self.lbl_top_user = ClickableLabel("👤 En Aktif Kullanıcı: -")
        self.lbl_top_event_id = ClickableLabel("🆔 En Sık Event ID: -")

        self.notifications_enabled = False

        self.status_queue = []
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.process_status_queue)
        self.status_timer.start(2500) # Her 2.5 saniyede bir sıradaki bildirimi gösterir

        self.lbl_total.clicked.connect(
            lambda: self.clear_filter()
        )

        self.lbl_suspicious.clicked.connect(
            lambda: self.quick_filter("Risk Seviyesi", "Suspicious")
        )

        self.lbl_critical.clicked.connect(
            lambda: self.quick_filter("Risk Seviyesi", "Critical")
        )
        self.lbl_suspicious.clicked.connect(lambda: self.quick_filter("Risk Seviyesi", "suspicious")) # 🚀 YENİ EKLENDİ
        self.lbl_risk_dist.clicked.connect(self.select_risk_level_dialog) 
        
        self.top_ip_value = "-"
        self.top_user_value = "-"
        self.top_event_id_value = "-"

        self.lbl_top_ip.clicked.connect(lambda: self.quick_filter("IP Adresi", self.top_ip_value))
        self.lbl_top_user.clicked.connect(lambda: self.quick_filter("Kullanıcı", self.top_user_value))
        self.lbl_top_event_id.clicked.connect(lambda: self.quick_filter("Event ID", self.top_event_id_value))

        font = QFont(); font.setBold(True); font.setPointSize(11)
        # 🚀 YENİ: self.lbl_suspicious listeye eklendi
        labels = [
            self.lbl_total,
            self.lbl_suspicious,
            self.lbl_critical,
            self.lbl_risk_dist,
            self.lbl_top_ip,
            self.lbl_top_user,
            self.lbl_top_event_id
        ]
        for lbl in labels:
            lbl.setFont(font)
            lbl.setStyleSheet("color: #4a90e2; text-decoration: underline; cursor: pointer;")
            
        dashboard_layout.addWidget(self.lbl_total, 0, 0)
        dashboard_layout.addWidget(self.lbl_suspicious, 0, 1)
        dashboard_layout.addWidget(self.lbl_critical, 0, 2)

        dashboard_layout.addWidget(self.lbl_risk_dist, 1, 0, 1, 3)

        dashboard_layout.addWidget(self.lbl_top_ip, 2, 0)
        dashboard_layout.addWidget(self.lbl_top_user, 2, 1)
        dashboard_layout.addWidget(self.lbl_top_event_id, 2, 2)
        
        self.dashboard_group.setLayout(dashboard_layout)
        main_layout.addWidget(self.dashboard_group) 

        self.btn_security_live = QPushButton("🛡️ Windows Security Canlı İzle")
        self.btn_security_live.clicked.connect(self.toggle_security_live_mode)
        main_layout.addWidget(self.btn_security_live)

        button_layout = QHBoxLayout()
        self.btn_load_log = QPushButton("📁 Log Dosyası Yükle (.csv / .evtx)")
        self.btn_load_log.setMinimumHeight(40)
        self.btn_load_log.clicked.connect(self.load_log_file)
        button_layout.addWidget(self.btn_load_log)

        self.btn_export = QPushButton("📥 Analiz Raporunu İndir")
        self.btn_export.setMinimumHeight(40)
        self.btn_export.clicked.connect(self.export_report)
        self.btn_export.setEnabled(False)
        button_layout.addWidget(self.btn_export)

        self.btn_timeline = QPushButton("🕒 Olay Zaman Çizelgesi")
        self.btn_timeline.setMinimumHeight(40)
        self.btn_timeline.clicked.connect(self.show_timeline)
        button_layout.addWidget(self.btn_timeline)
        
        self.btn_manage_blocks = QPushButton("🛡️ Güvenlik Duvarı && Whitelist")
        self.btn_manage_blocks.setMinimumHeight(40)
        self.btn_manage_blocks.clicked.connect(self.show_blocked_ips_manager)
        button_layout.addWidget(self.btn_manage_blocks)
        main_layout.addLayout(button_layout)

        ioc_layout = QHBoxLayout()
        ioc_layout.addWidget(QLabel("🛡️ IOC Tehdit İstihbarat Modu:"))
        self.combo_ioc_mode = QComboBox()
        self.combo_ioc_mode.addItems(["Yerel Veritabanı (Offline)", "VirusTotal Canlı Sorgu (Online)"])
        self.combo_ioc_mode.setMinimumHeight(30)
        ioc_layout.addWidget(self.combo_ioc_mode)
        main_layout.addLayout(ioc_layout)

        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filtrele:"))
        self.filter_column = QComboBox()
        self.filter_column.addItems([
            "Tümü", "Tarih", "Saat", "Event ID", "Kullanıcı", 
            "IP Adresi", "Durum", "Kaynak", "Olay Tipi", "Risk Seviyesi", "Tespit Nedeni"
        ])
        filter_layout.addWidget(self.filter_column)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Aramak istediğiniz değeri yazın...")
        self.filter_input.returnPressed.connect(self.apply_filter)
        filter_layout.addWidget(self.filter_input)
        self.btn_filter = QPushButton("🔍 Ara")
        self.btn_filter.clicked.connect(self.apply_filter)
        filter_layout.addWidget(self.btn_filter)
        self.btn_clear_filter = QPushButton("❌ Temizle")
        self.btn_clear_filter.clicked.connect(self.clear_filter)
        filter_layout.addWidget(self.btn_clear_filter)
        main_layout.addLayout(filter_layout) 

        self.log_table = QTableWidget()
        self.log_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.log_table.setColumnCount(10)
        self.log_table.setHorizontalHeaderLabels([
            "Tarih", "Saat", "Event ID", "Kullanıcı", "IP Adresi", 
            "Durum", "Kaynak", "Olay Tipi", "Risk Seviyesi", "Tespit Nedeni"
        ])
        # Sütun genişlikleri (isteğe bağlı düzenleyebilirsin)
        self.log_table.setColumnWidth(0, 100) 
        self.log_table.setColumnWidth(1, 90)  
        self.log_table.setColumnWidth(2, 200)  
        self.log_table.setColumnWidth(3, 110) 
        self.log_table.setColumnWidth(4, 120) 
        self.log_table.setColumnWidth(5, 110) 
        self.log_table.setColumnWidth(6, 90)  
        self.log_table.setColumnWidth(7, 130) 
        self.log_table.setColumnWidth(8, 100) 
        self.log_table.setColumnWidth(9, 150)
        main_layout.addWidget(self.log_table)
        self.log_table.cellDoubleClicked.connect(self.show_event_details)
        self.log_table.cellDoubleClicked.connect(self.manual_block_from_table)

        self.log_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        self.current_file = None
        
        # 🚀 Performans için deque + set senkronize yapısı:
        self.seen_logs_deque = deque(maxlen=10000)
        self.seen_logs_set = set()

        self.dashboard_stats = {
            "total": 0,
            "suspicious": 0,
            "risk": {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0,
                "Fatal": 0
            },
            "ips": {},
            "users": {},
            "events": {},
            "detections": {}
        }

        # =========================================================
        # ANA OLAY DEPOSU
        # QTableWidget veri kaynağı değildir.
        # Tüm analiz edilen olaylar burada tutulur.
        # =========================================================
        self.analyzed_events = []

        # Olay korelasyonu için geçmiş
        self.event_history = []

        # Dosya analiz bilgileri
        self.current_file_hash = "-"
        self.current_file_name = "-"
        self.analysis_start_time = None
        self.analysis_end_time = None


        # 🚀 1. GÜVENLİ DOSYA YOLU MİMARİSİ (Çalışma dizini bağımlılığını koparır)
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        ioc_path = os.path.join(BASE_DIR, "ioc_list.json")

        self.known_malicious_ips = []
        self.test_ips = []
        self.whitelisted_ips = set() # 🎯 2. Kalıcı Whitelist Kümesi
        
        # 3. JSON verilerini güvenli yoldan ve whitelist dahil yükleme
        if os.path.exists(ioc_path):
            try:
                with open(ioc_path, "r", encoding="utf-8") as f:
                    ioc_data = json.load(f)
                    self.known_malicious_ips = ioc_data.get("malicious_ips", [])
                    self.test_ips = ioc_data.get("test_ips", [])
                    self.whitelisted_ips = set(ioc_data.get("whitelisted_ips", []))
            except Exception as e:
                print(f"IOC dosyası okunamadı: {e}")
        else:
            # JSON dosyası henüz yoksa yedek:
            self.test_ips = ["10.0.0.99"]

    def save_ioc_data(self):
        BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        ioc_path = os.path.join(BASE_DIR, "ioc_list.json")
        try:
            ioc_data = {
                "malicious_ips": self.known_malicious_ips,
                "test_ips": self.test_ips,
                "whitelisted_ips": list(self.whitelisted_ips)
            }
            with open(ioc_path, "w", encoding="utf-8") as f:
                json.dump(ioc_data, f, indent=4, ensure_ascii=False)
        except Exception as e:
            print(f"IOC dosyası kaydedilemedi: {e}")

    def quick_filter(self, column, value):
        self.filter_column.setCurrentText(column)
        self.filter_input.setText(value)
        self.apply_filter()

    def reset_dashboard_stats(self):
        self.dashboard_stats = {
            "total": 0,
            "suspicious": 0,
            "risk": {
                "Low": 0,
                "Medium": 0,
                "High": 0,
                "Critical": 0,
                "Fatal": 0
            },
            "ips": {},
            "users": {},
            "events": {},
            "detections": {}
        }
        self.update_dashboard()  

    def register_dashboard_stat(
        self,
        event_id,
        user,
        ip,
        risk_level,
        detection=""
    ):
        stats = self.dashboard_stats

        stats["total"] += 1

        risk_name = (
            risk_level
            .replace("🟢 ", "")
            .replace("🟡 ", "")
            .replace("🟠 ", "")
            .replace("🔴 ", "")
            .replace("☠️ ", "")
            .strip()
        )

        if risk_name in stats["risk"]:
            stats["risk"][risk_name] += 1

        # Medium ve üstü olayları şüpheli kabul ediyoruz.
        if risk_name in ["Medium", "High", "Critical", "Fatal"]:
            stats["suspicious"] += 1

        if ip and ip != "-":
            stats["ips"][ip] = stats["ips"].get(ip, 0) + 1

        if user and user != "-":
            stats["users"][user] = stats["users"].get(user, 0) + 1

        event_id = str(event_id).strip()

        if event_id and event_id != "-":
            stats["events"][event_id] = (
                stats["events"].get(event_id, 0) + 1
            )

        if detection and detection != "Normal Aktivite":
            stats["detections"][detection] = (
                stats["detections"].get(detection, 0) + 1
            )

    def select_risk_level_dialog(self):
        risk_seviyeleri = ["Low", "Medium", "High", "Critical", "Fatal"]
        secim, ok = QInputDialog.getItem(self, "Risk Seviyesi Seç", "Filtrelemek istediğiniz risk seviyesini seçin:", risk_seviyeleri, 0, False)
        if ok and secim: self.quick_filter("Risk Seviyesi", secim)

    def update_dashboard(self):
        stats = self.dashboard_stats

        total = stats.get("total", 0)
        # 🚀 Küçük/büyük harf uyumsuzluğuna karşı iki ihtimali de güvenle alıyoruz
        suspicious = stats.get("suspicious", stats.get("Suspicious", 0)) 

        if total == 0:
            self.lbl_total.setText("Toplam Olay: 0")
            self.lbl_critical.setText("🔴 Kritik Olay: 0")
            self.lbl_suspicious.setText("🚨 Şüpheli Olay: 0")
            self.lbl_risk_dist.setText(
                "📊 Risk Dağılımı: 🟢 Low: 0 | 🟡 Medium: 0 | "
                "🟠 High: 0 | 🔴 Critical: 0 | ☠️ Fatal: 0"
            )
            self.lbl_top_ip.setText("🌐 En Aktif IP: -")
            self.lbl_top_user.setText("👤 En Aktif Kullanıcı: -")
            self.lbl_top_event_id.setText("🆔 En Sık Event ID: -")
            return

        risk = stats.get("risk", {})

        en_aktif_ip = max(stats["ips"], key=stats["ips"].get) if stats.get("ips") else "-"
        en_aktif_user = max(stats["users"], key=stats["users"].get) if stats.get("users") else "-"
        en_sik_event = max(stats["events"], key=stats["events"].get) if stats.get("events") else "-"

        self.top_ip_value = en_aktif_ip
        self.top_user_value = en_aktif_user
        self.top_event_id_value = str(en_sik_event).split(" ")[0] if en_sik_event != "-" else "-"

        self.lbl_total.setText(
            f'<span style="color: #66b3ff;">Toplam Olay: {total}</span>'
        )
        self.lbl_suspicious.setText(
            f'<span style="color: #ff9800;">'
            f'🚨 Şüpheli Olay: {stats["suspicious"]}'
            f'</span>'
        )

        self.lbl_critical.setText(
            f'<span style="color: #ff6666;">'
            f'🔴 Kritik Olay: {risk.get("Critical", 0) + risk.get("Fatal", 0)}'
            f'</span>'
        )

        # 🚀 İŞTE EKSİK OLAN VE SAYIYI EKRANA BASACAK KISIM BURASI:
        self.lbl_suspicious.setText(
            f'<span style="color: #ffb74d;">'
            f'🚨 Şüpheli Olay: {suspicious}'
            f'</span>'
        )

        self.lbl_risk_dist.setText(
            f'📊 Risk Dağılımı: '
            f'🟢 Low: {risk.get("Low", 0)} | '
            f'🟡 Medium: {risk.get("Medium", 0)} | '
            f'🟠 High: {risk.get("High", 0)} | '
            f'🔴 Critical: {risk.get("Critical", 0)} | '
            f'☠️ Fatal: {risk.get("Fatal", 0)}'
        )

        self.lbl_top_ip.setText(
            f'<span style="color: #66b3ff;">🌐 En Aktif IP: {en_aktif_ip}</span>'
        )

        self.lbl_top_user.setText(
            f'<span style="color: #ffb74d;">👤 En Aktif Kullanıcı: {en_aktif_user}</span>'
        )

        self.lbl_top_event_id.setText(
            f'<span style="color: #b366ff;">🆔 En Sık Event ID: {en_sik_event}</span>'
        )

    def manual_block_from_table(self, row, column):
        # Sadece IP Adresi sütununa (4. sütun) tıklandıysa çalışır
        if column != 4:
            return
            
        ip_item = self.log_table.item(row, 4)
        if not ip_item: return
        
        ip_address = ip_item.text().strip()
        
        # IP boşsa, "-" ise veya localhost ise işlem yapma
        if not ip_address or ip_address == "-" or ip_address == "127.0.0.1":
            return
            
        
        # 🚀 YENİ: Whitelist (Güvenilir Liste) Kontrolü ve Akıllı Diyalog
        if hasattr(self, 'whitelisted_ips') and ip_address in self.whitelisted_ips:
            cevap = QMessageBox.warning(
                self,
                "⚠️ Whitelist Uyarısı",
                f"Dikkat: {ip_address} adresi şu anda Güvenilir Listede (Whitelist) yer alıyor.\n\nBuna rağmen bu IP adresini güvenlik duvarında manuel olarak engellemek istiyor musunuz?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No  # Varsayılanı 'No' yaparak kazaları önlüyoruz
            )
        else:
            # Standart Onay Penceresi (IP Whitelist'te değilse)
            cevap = QMessageBox.question(
                self, 
                "🎯 Manuel Hedefleme", 
                f"Seçilen IP: {ip_address}\n\nBu IP adresini güvenlik duvarında manuel olarak engellemek istiyor musunuz?", 
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )
        
        if cevap == QMessageBox.StandardButton.Yes:
            if self.block_ip_in_firewall(ip_address):
                # 🚀 AUDIT LOG: Kullanıcının yaptığı manuel engellemeyi denetim kaydına ekle
                if hasattr(self, 'add_audit_log'):
                    self.add_audit_log(f"MANUEL ENGELLEME: {ip_address} adresi kullanıcı tarafından güvenlik duvarına eklendi.")
                
                QMessageBox.information(
                    self, 
                    "Manuel Müdahale Başarılı", 
                    f"Seçilen IP ({ip_address}) güvenlik duvarında başarıyla engellendi."
                )
            else:
                # Başarısız olduysa block_ip_in_firewall içinde zaten QMessageBox.critical ile yetki hatası gösteriliyordur,
                # bu yüzden ekstra başarı mesajı gösterilmez.
                pass

    def load_log_file(self):

        if hasattr(self, 'timer') and self.timer.isActive():
            self.timer.stop()

        if hasattr(self, 'worker'):
            self.stop_worker_safely(self.worker)

        if hasattr(self, 'live_worker'):
            self.stop_worker_safely(self.live_worker)

        if hasattr(self, 'security_timer') and self.security_timer.isActive():
            self.security_timer.stop()
            self.is_security_live_active = False

            self.btn_security_live.setText(
                "🛡️ Windows Security Canlı İzle"
            )
            self.btn_security_live.setStyleSheet("")

        file_path, _ = QFileDialog.getOpenFileName(
            self, "Log Dosyası Seç", "", "Log Dosyaları (*.csv *.evtx);;Tüm Dosyalar (*.*)"
        )
        
        if file_path:
            # 🚀 DÜZELTİLEN KISIM: Hash hesaplama ve loglama işlemi en başa alındı!
            self.current_file_name = os.path.basename(file_path)
            self.current_file_hash = self.calculate_file_hash(file_path)
            self.analysis_start_time = datetime.now()
            
            if hasattr(self, 'add_audit_log'):
                self.add_audit_log(
                    f"ANALİZ BAŞLATILDI | "
                    f"Dosya={self.current_file_name} | "
                    f"SHA256={self.current_file_hash}"
                )
            # ---------------------------------------------------------

            if hasattr(self, 'log_table'):
                self.log_table.setRowCount(0)

            self.seen_logs_deque.clear()
            self.seen_logs_set.clear()
            self.reset_dashboard_stats()
            self.failed_attempts = {}
            self.current_fatal_alerts = []
            self.current_file = file_path
            
            if file_path.lower().endswith(".csv"):
                cevap = QMessageBox.question(
                    self, 
                    "Canlı Dosya İzleme Modu", 
                    "Seçtiğiniz CSV dosyasını canlı olarak takip etmek (arkaya eklenen yeni satırları anlık okumak) ister misiniz?\n\n"
                    "EVET: Dosyayı canlı takip et (Tail)\n"
                    "HAYIR: Klasik tek seferlik analiz",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                
                if cevap == QMessageBox.StandardButton.Yes:
                    self.notifications_enabled = True
                    self.status_queue.clear()

                    self.file_read_position = 0
                    self.start_live_timer()
                    self.run_live_file_update()
                    return
                else:
                    # STATİK CSV ANALİZİ
                    self.notifications_enabled = False
                    self.status_queue.clear()

                    self.process_file(
                        file_path=file_path,
                        show_popup=True,
                        scan_mode="csv"
                    )
            else:
                # STATİK EVTX ANALİZİ
                self.notifications_enabled = False
                self.status_queue.clear()

                self.process_file(
                    file_path=file_path,
                    show_popup=True,
                    scan_mode="file"
                )      

    def process_file(self, file_path, show_popup=False, scan_mode="gecmis_evtx"):

        # 🚀 YARIŞ DURUMU (RACE CONDITION) KORUMASI:
        # Eski iş parçacığı (thread) hâlâ çalışıyorsa, yeni bir döngü başlatma!
        if hasattr(self, "worker") and self.worker.isRunning():
            return

        ioc_mode = self.combo_ioc_mode.currentText() if hasattr(self, 'combo_ioc_mode') else "Yerel"
        # 🚀 Hassas VT_API_KEY satırı tamamen kaldırıldı! Artık ortam değişkeninden güvenli okunuyor.

        self.btn_load_log.setText("⏹️ Akışı Durdur (İptal Et)")
        self.btn_load_log.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold;")
        
        try: self.btn_load_log.clicked.disconnect()
        except RuntimeError: pass
        self.btn_load_log.clicked.connect(self.stop_analysis_worker)
        
        self.current_fatal_alerts = [] 
        
        # 🚀 Test IP'lerini güvenle alıyoruz
        current_test_ips = getattr(self, 'test_ips', set())
        
        # Worker çağrısından vt_api_key parametresi uçuruldu
        # 🚀 Yeni hali (Ana penceredeki self.last_seen_record_id değerini ve test_ips'i işçiye yolluyoruz):
        self.worker = LogWorker(
            file_path, 
            ioc_mode, 
            self.known_malicious_ips, 
            scan_mode, 
            last_seen_record_id=self.last_seen_record_id,
            test_ips=current_test_ips  # 🚀 EKSİK OLAN KISIM BURAYA EKLENDİ
        )
        
        if scan_mode == "file":
            self.worker.logs_batch_ready.connect(self.add_log_rows_batch)
        else:
            self.worker.log_ready.connect(self.add_single_log_row_live)
        self.worker.analysis_finished.connect(lambda count: self.on_analysis_finished(count, show_popup, scan_mode))
        self.worker.error.connect(self.on_analysis_error)
        self.worker.start()

    def stop_analysis_worker(self):
        # Canlı izlemeyi durdur
        if hasattr(self, 'timer') and self.timer.isActive():
            self.timer.stop()
            if hasattr(self, 'btn_live'):
                self.btn_live.setText("▶ Canlı İzlemeyi Başlat (Live Sync)")
                self.btn_live.setStyleSheet("")

        # Arka plan işçisine durma talebi gönder
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.requestInterruption()
            
            # Kullanıcıya bilgi ver ve yeni dosya yüklemeyi geçici kısıtla
            if hasattr(self, 'statusBar'):
                self.statusBar().showMessage("İşlem durduruluyor, lütfen bekleyin...", 3000)
            
            if hasattr(self, 'btn_load_log'):
                self.btn_load_log.setEnabled(False) # Arka plan temizlenene kadar kilitli kalır
                
    def reset_load_button(self):
        self.btn_load_log.setText("📁 Log Dosyası Yükle (.csv / .evtx)")
        self.btn_load_log.setStyleSheet("")
        try: self.btn_load_log.clicked.disconnect()
        except RuntimeError: pass
        self.btn_load_log.clicked.connect(self.load_log_file)
        self.btn_load_log.setEnabled(True)

    def on_analysis_finished(self, total_count, show_popup, scan_mode):
        if total_count > 0:
            self.btn_export.setEnabled(True)

        if hasattr(self, 'btn_load_log'):
            self.btn_load_log.setEnabled(True)

        # Sadece statik dosya yüklenmişse bu logu atıyoruz (Canlı izlemede dosya adı olmayabilir)
        if getattr(self, 'current_file', None):
            self.analysis_end_time = datetime.now()
            self.add_audit_log(
                f"ANALİZ TAMAMLANDI | "
                f"Dosya={self.current_file_name} | "
                f"Toplam={total_count}"
            )    

        if scan_mode == "live_security":
            if hasattr(self, 'live_worker') and hasattr(self.live_worker, 'last_seen_record_id'):
                self.last_seen_record_id = self.live_worker.last_seen_record_id
            
        # 🚀 PERFORMANS İYİLEŞTİRMESİ VE BUTON DÜZELTMESİ: 
        # Sadece geçmiş taramalarda butonu sıfırla ve tabloyu boyutlandır. Canlı modda bunlara dokunma!
        if scan_mode != "live_security":
            self.reset_load_button()
            
        self.update_dashboard()
        

        # 1. MEVCUT: FATAL Uyarılar Özeti
        if hasattr(self, 'current_fatal_alerts') and self.current_fatal_alerts and show_popup:
            unique_alerts = list(set(self.current_fatal_alerts))
            unique_alerts.sort(reverse=True)
            html_kayitlar = "<br>".join(unique_alerts)
            html_mesaj = f"<h3>🚨 DİKKAT! Log dosyasında Kritik (FATAL) seviyede tehditler tespit edildi!</h3><b>Bulunan Kayıtlar:</b><br><br>{html_kayitlar}"
            uyari = QMessageBox(self)
            uyari.setWindowTitle("KRİTİK GÜVENLİK UYARISI")
            uyari.setIcon(QMessageBox.Critical)
            uyari.setText(html_mesaj)
            ekran = QApplication.primaryScreen().availableGeometry()
            uyari.move((ekran.width() - 400) // 2, (ekran.height() - 200) // 2)
            uyari.exec()
            self.current_fatal_alerts = []

        # 🎯 2. YENİ EKLENEN: Otomatik Engelleme (IPS) Özeti
        if hasattr(self, 'session_blocked_ips') and self.session_blocked_ips and show_popup:
            ip_listesi_str = "\n".join([f"• {ip}" for ip in self.session_blocked_ips])
            mesaj = f"Tarama Tamamlandı!\n\nAşağıdaki {len(self.session_blocked_ips)} zararlı IP adresi tespit edilip güvenlik duvarında otomatik olarak engellendi:\n\n{ip_listesi_str}"
            QMessageBox.information(self, "🛡️ Otomatik Savunma Raporu", mesaj)
            # Gösterdikten sonra hafızayı sıfırla ki bir sonraki taramada eskileri tekrar göstermesin
            self.session_blocked_ips.clear()

    def on_analysis_error(self, err_msg):
        # 🚀 Hata durumunda canlı izleme (timer) aktifse mutlaka durdurmalıyız
        if hasattr(self, 'security_timer') and self.security_timer.isActive():
            self.security_timer.stop()
            self.is_security_live_active = False

            if hasattr(self, 'btn_live'):
                self.btn_live.setText("▶ Canlı İzlemeyi Başlat (Live Sync)")
                self.btn_live.setStyleSheet("")

        # Yükleme butonunu ve arayüzü güvenli duruma getir
        self.reset_load_button()
        
        # Gerekirse kullanıcıya hata bildirimi
        if hasattr(self, 'statusBar'):
            self.statusBar().showMessage(f"Hata Oluştu: {err_msg}", 5000)


    def handle_worker_error(self, error_message):
        """Arka plan işçisinde (worker) oluşan hataları yakalar ve konsola bildirir."""
        print(f"Canlı İzleme Hatası: {error_message}")

    def run_live_file_update(self):
        if hasattr(self, 'live_worker') and self.live_worker.isRunning():
            return

        if not hasattr(self, 'file_read_position'):
            self.file_read_position = 0

        ioc_mode = self.combo_ioc_mode.currentText() if hasattr(self, 'combo_ioc_mode') else "Yerel Veritabanı (Offline)"
        malicious_ips = getattr(self, 'known_malicious_ips', set())
        
        # 🚀 Test IP'lerini de güvenle alıyoruz
        current_test_ips = getattr(self, 'test_ips', set())

        # scan_mode parametresini "live_file" olarak veriyoruz ve test_ips'i iletiyoruz
        self.live_worker = LogWorker(
            file_path=self.current_file, 
            ioc_mode=ioc_mode, 
            known_malicious_ips=malicious_ips, 
            scan_mode="live_file",
            last_seen_record_id=self.file_read_position,
            test_ips=current_test_ips  # 🚀 EKSİK OLAN KISIM BURAYA EKLENDİ
        )
        self.live_worker.log_ready.connect(self.add_single_log_row_live)
        self.live_worker.error.connect(self.handle_worker_error)

        # Worker her pozisyon güncellediğinde ana sınıftaki imleci tazele
        self.live_worker.position_updated.connect(lambda pos: setattr(self, 'file_read_position', pos))
        
        self.live_worker.start()

    def run_live_update(self):
        # Eğer hâlâ devam eden bir canlı worker varsa üst üste bindirme
        if hasattr(self, 'live_worker') and self.live_worker.isRunning():
            return

        ioc_mode = self.combo_ioc_mode.currentText() if hasattr(self, 'combo_ioc_mode') else "Yerel Veritabanı (Offline)"
        malicious_ips = getattr(self, 'known_malicious_ips', set())
        current_test_ips = getattr(self, 'test_ips', set())
        
        # Güvenli olması için last_seen_record_id'yi ana sınıftan alıyoruz (yoksa varsayılan 0)
        current_last_id = getattr(self, 'last_seen_record_id', 0)

        self.live_worker = LogWorker(
            file_path="", 
            ioc_mode=ioc_mode, 
            known_malicious_ips=malicious_ips, 
            scan_mode="live_security",
            last_seen_record_id=current_last_id,  # 🚀 İŞTE KRİTİK EKSİK BURAYA EKLENDİ
            test_ips=current_test_ips
        )
        
        # Sinyal bağlantıları
        self.live_worker.log_ready.connect(self.add_single_log_row_live)
        self.live_worker.error.connect(self.handle_worker_error)
        self.live_worker.analysis_finished.connect(lambda count: self.on_analysis_finished(count, False, "live_security"))
        
        # 🚀 KRİTİK BAĞLANTI: Gerçek EventRecordID'yi güncelleyen sinyal
        self.live_worker.security_last_id_updated.connect(self.update_security_last_id)

        self.live_worker.start()

    def apply_filter(self):
        search_text = self.filter_input.text().lower() 
        selected_column = self.filter_column.currentText()

        column_map = {
            "Tarih": 0, 
            "Saat": 1, 
            "Event ID": 2, 
            "Kullanıcı": 3, 
            "IP Adresi": 4, 
            "Durum": 5, 
            "Kaynak": 6,          
            "Olay Tipi": 7,       
            "Risk Seviyesi": 8,   
            "Tespit Nedeni": 9    
        }

        for row in range(self.log_table.rowCount()):
            match = False
            if selected_column == "Tümü":
                for col in range(self.log_table.columnCount()):
                    item = self.log_table.item(row, col)
                    if item and search_text in item.text().lower(): 
                        match = True
                        break
            else:
                col_idx = column_map[selected_column]
                item = self.log_table.item(row, col_idx)
                if item:
                    item_text = item.text().lower()
                    # 🚀 UX DÜZELTMESİ: "Risk Seviyesi" aramaları
                if selected_column == "Risk Seviyesi":
                    if search_text == "critical":
                        if "critical" in item_text or "fatal" in item_text:
                            match = True
                    elif search_text == "suspicious": # 🚀 YENİ EKLENEN KISIM
                        if any(level in item_text for level in ["medium", "high", "critical", "fatal"]):
                            match = True
                    elif search_text in item_text:
                        match = True
                elif search_text in item_text:
                    match = True
                        
            self.log_table.setRowHidden(row, not match)

        self.update_dashboard()    
            

    def clear_filter(self):
        # Filtre inputlarını temizle
        if hasattr(self, 'filter_input'):
            self.filter_input.clear()
        if hasattr(self, 'filter_column'):
            self.filter_column.setCurrentIndex(0) # "Tümü" seçeneğine sıfırla

        # Tablodaki tüm gizlenmiş satırları yeniden görünür yap
        for row in range(self.log_table.rowCount()):
            self.log_table.setRowHidden(row, False)

        self.update_dashboard()    
            

    def on_firewall_success(self, ip):
        if hasattr(self, 'session_blocked_ips'):
            self.session_blocked_ips.add(ip)
        # 🚀 Yeni engellendiği an audit log'a işlenir
        if hasattr(self, 'add_audit_log'):
            self.add_audit_log(f"OTOMATİK ENGELLEME (YENİ): {ip} adresi güvenlik duvarında engellendi.")

    def on_firewall_already_blocked(self, ip):
        """IP adresi halihazırda Windows Güvenlik Duvarı'nda engellenmiş durumdaysa tetiklenir."""

        if hasattr(self, 'add_audit_log'):
            self.add_audit_log(f"OTOMATİK KONTROL: {ip} adresi zaten güvenlik duvarında engelliydi.")

    def on_firewall_error(self, ip_address, error_msg):
        print(f"[!] Hata: {ip_address} engellenemedi. Detay: {error_msg}")


    def show_blocked_ips_manager(self):
        modlar = [
            "⛔ Engellenen IP'leri Listele (Engeli Kaldır)", 
            "✅ Beyaz Liste Yönetimi", 
            "📜 İşlem Geçmişi (Denetim Kaydı)"
        ]
        secilen_mod, ok = QInputDialog.getItem(self, "🛡️ IP Yönetim Paneli", "İşlem:", modlar, 0, False)
        if not ok: return
        
        # 1. MOD: ENGELLENEN IP YÖNETİMİ VE ENGEL KALDIRMA
        if "⛔ Engellenen" in secilen_mod:
            engellenenler = []
            try:
                # 🛡️ GÜVENLİK 1: Tüm kuralları listelerken shell=False ve liste yapısı
                komut_liste = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
                result = subprocess.run(komut_liste, capture_output=True, text=True, encoding='cp857', errors='ignore')
                
                for line in result.stdout.splitlines():
                    if "WinLogSentinel_Block_" in line:
                        ip = line.split("WinLogSentinel_Block_")[1].strip()
                        if ip not in engellenenler: engellenenler.append(ip)
            except Exception: pass
            
            if not engellenenler: QMessageBox.information(self, "Bilgi", "Güvenlik duvarında engellenen IP yok."); return
            
            secilen_ip, ok = QInputDialog.getItem(self, "Engellenenler", "Engelini kaldır:", engellenenler, 0, False)
            if ok and secilen_ip:
                # 🛡️ GÜVENLİK 2: Kuralı silmeden önce IP'yi doğrula
                try:
                    ipaddress.ip_address(secilen_ip)
                except ValueError:
                    QMessageBox.warning(self, "Hata", "Geçersiz IP adresi tespit edildi! İşlem iptal edildi.")
                    return
                
                # 🛡️ GÜVENLİK 3: Silme işleminde shell=False ve liste yapısı
                silme_komutu = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=WinLogSentinel_Block_{secilen_ip}"]
                
                result = subprocess.run(
                    silme_komutu,
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    # İşlemi merkezileştirilmiş audit log fonksiyonuyla kaydet
                    if hasattr(self, 'add_audit_log'):
                        self.add_audit_log(f"🔓 {secilen_ip} IP adresinin engeli kaldırıldı.")
                        
                    QMessageBox.information(self, "Başarılı", f"{secilen_ip} engeli kaldırıldı ve geçmişe kaydedildi.")
                else:
                    QMessageBox.critical(
                        self,
                        "Hata",
                        f"Firewall kuralı kaldırılamadı. Yetkinizi kontrol edin.\n\nHata: {result.stderr.strip()}"
                    )
                
        # 2. MOD: BEYAZ LİSTE (WHITELIST) YÖNETİMİ
        elif "✅ Beyaz" in secilen_mod:
            
            w_modlar = ["📋 Listele", "➕ Yeni IP Ekle", "➖ IP Çıkar"]
            bilgi_notu = "Ne yapmak istiyorsun?\n\n(ℹ️ Not: Beyaz liste yalnızca güvenlik duvarı engellemesini devre dışı bırakır. Tablodaki risk uyarılarını gizlemez.)"
            w_secim, ok = QInputDialog.getItem(self, "Beyaz Liste", bilgi_notu, w_modlar, 0, False)
            if not ok: return
            
            if "📋 Listele" in w_secim:
                liste_str = "\n".join(self.whitelisted_ips) if self.whitelisted_ips else "Beyaz liste şu an boş."
                QMessageBox.information(self, "Beyaz Liste", f"Güvenilir IP Adresleri:\n\n{liste_str}\n\n* Bu listedeki IP'ler için otomatik firewall savunması devre dışıdır.")
                
            elif "➕ Yeni IP Ekle" in w_secim:
                                yeni_ip, ok = QInputDialog.getText(self, "Beyaz Liste", "Güvenilir IP adresini girin (Örn: 192.168.1.15):")
                                if ok and yeni_ip.strip():
                                    # 🛡️ GÜVENLİK 4: Beyaz listeye eklerken bile hatalı veri girişini engelle
                                    try:
                                        ipaddress.ip_address(yeni_ip.strip())
                                        self.whitelisted_ips.add(yeni_ip.strip())
                                        
                                        if hasattr(self, 'add_audit_log'):
                                            self.add_audit_log(f"WHİTELİST'E EKLEME: {yeni_ip.strip()} adresi beyaz listeye dahil edildi.")
                                        
                                        if hasattr(self, 'save_ioc_data'):
                                            self.save_ioc_data()
                                            
                                        QMessageBox.information(self, "Başarılı", f"{yeni_ip} beyaz listeye eklendi.\nArtık güvenlik duvarında engellenmeyecek ancak şüpheli aktiviteleri tabloda gösterilmeye devam edecek.")
                                    except ValueError:
                                        QMessageBox.warning(self, "Hata", "Lütfen geçerli bir IPv4 veya IPv6 adresi girin!")
                    
            elif "➖ IP Çıkar" in w_secim:
                                if not self.whitelisted_ips:
                                    QMessageBox.information(self, "Bilgi", "Beyaz liste zaten boş.")
                                    return
                                silinecek_ip, ok = QInputDialog.getItem(self, "Beyaz Liste", "Çıkarılacak IP:", list(self.whitelisted_ips), 0, False)
                                if ok and silinecek_ip:
                                    self.whitelisted_ips.remove(silinecek_ip)
                                    
                                    if hasattr(self, 'add_audit_log'):
                                            self.add_audit_log(f"WHİTELİST'TEN ÇIKARMA: {silinecek_ip} adresi beyaz listeden kaldırıldı.")
                                        
                                    if hasattr(self, 'save_ioc_data'):
                                            self.save_ioc_data()
                                        
                                    QMessageBox.information(self, "Başarılı", f"{silinecek_ip} beyaz listeden çıkarıldı.")
                    
        # 3. MOD: İŞLEM GEÇMİŞİ (AUDIT LOG)
        elif "📜 İşlem" in secilen_mod:
            try:
                # 🚀 DÜZELTME: Mutlak dosya yolu tanımlandı
                BASE_DIR = os.path.dirname(os.path.abspath(__file__))
                audit_path = os.path.join(BASE_DIR, "denetim_kaydi.txt")

                # "denetim_kaydi.txt" yerine audit_path kullanıldı
                if not os.path.exists(audit_path):
                    QMessageBox.information(self, "İşlem Geçmişi", "Henüz kaydedilmiş bir engel kaldırma işlemi yok.")
                    return
                    
                # "denetim_kaydi.txt" yerine audit_path kullanıldı
                with open(audit_path, "r", encoding="utf-8") as f:
                    satirlar = [satir.strip() for satir in f if satir.strip()]

                satirlar.reverse()
                gecmis = "\n".join(satirlar)
                    
                if not gecmis:
                    QMessageBox.information(self, "İşlem Geçmişi", "Geçmiş kaydı boş.")
                    return
                    
                msg = QMessageBox(self)
                msg.setWindowTitle("📜 İşlem Geçmişi")
                msg.setText("Sistemdeki işlemler geçmişte kayıtlıdır.\nKayıtları görmek için 'Show Details...' (Ayrıntıları Göster) butonuna tıklayın.")
                msg.setDetailedText(gecmis)
                msg.exec()
                
            except Exception as e:
                QMessageBox.warning(self, "Hata", f"Geçmiş okunamadı: {e}")

    def show_timeline(self):
        if not getattr(self, 'analyzed_events', None):
            QMessageBox.information(
                self,
                "Timeline",
                "Gösterilecek analiz edilmiş olay bulunmuyor."
            )
            return

        dialog = TimelineDialog(
            self.analyzed_events,
            self
        )
        dialog.exec()

    def show_event_details(self, row, column):
        # Eğer yeni nesil sözlük (dictionary) sistemi aktifse ve kayıt varsa:
        if hasattr(self, 'analyzed_events') and len(self.analyzed_events) > row:
            event = self.analyzed_events[row]
            detay_mesaji = (
                f"Risk Seviyesi: {event.get('risk', '-')}\n"
                f"Score: {event.get('score', '0')}\n"
                f"Date / Time: {event.get('date', '-')} {event.get('time', '-')}\n"
                f"User: {event.get('user', '-')}\n"
                f"IP: {event.get('ip', '-')}\n"
                f"Hostname: {event.get('hostname', '-')}\n"
                f"Event ID: {event.get('event_id', '-')}\n"
                f"Event Type: {event.get('event_type', '-')}\n"
                f"Process: {event.get('process', '-')}\n"
                f"Source: {event.get('source', '-')}\n\n"
                f"📋 Detection:\n{event.get('detection', '-')}\n\n"
                f"💡 Recommended Action:\n{event.get('recommended_action', 'Sistem incelemesi devam ediyor.')}"
            )
        else:
            # Geçiş aşamasında eski satır (array) sisteminden okuma yedeği (Fallback)
            tarih = self.log_table.item(row, 0).text() if self.log_table.item(row, 0) else "-"
            saat = self.log_table.item(row, 1).text() if self.log_table.item(row, 1) else "-"
            event_id = self.log_table.item(row, 2).text() if self.log_table.item(row, 2) else "-"
            kullanici = self.log_table.item(row, 3).text() if self.log_table.item(row, 3) else "-"
            ip = self.log_table.item(row, 4).text() if self.log_table.item(row, 4) else "-"
            durum = self.log_table.item(row, 5).text() if self.log_table.item(row, 5) else "-"
            risk = self.log_table.item(row, 6).text() if self.log_table.item(row, 6) else "-"
            tespit = self.log_table.item(row, 7).text() if self.log_table.item(row, 7) else "-"

            detay_mesaji = (
                f"Risk Seviyesi: {risk}\n"
                f"Score: 0\n"
                f"Date / Time: {tarih} {saat}\n"
                f"User: {kullanici}\n"
                f"IP: {ip}\n"
                f"Event ID: {event_id}\n"
                f"Process: {durum}\n\n"
                f"📋 Detection:\n{tespit}\n\n"
                f"💡 Recommended Action:\nYeni detaylar sözlük analiz moduna geçildiğinde gösterilecektir."
            )

        uyari = QMessageBox(self)
        uyari.setWindowTitle("Detaylı Olay Analizi")
        uyari.setText(detay_mesaji)
        uyari.exec()

    def export_report(self):
        formatlar = ["Excel (.xlsx)", "CSV (.csv)", "JSON (.json)"]
        secim, ok = QInputDialog.getItem(self, "Rapor", "Format:", formatlar, 0, False)
        if not ok: return
        
        if not hasattr(self, 'analyzed_events') or not self.analyzed_events:
            QMessageBox.warning(self, "Uyarı", "Dışarı aktarılacak analiz edilmiş kayıt bulunamadı!")
            return

        # 🚀 Artık tabloyu değil, doğrudan arka plandaki büyük veritabanını kullanıyoruz
        df = pd.DataFrame(self.analyzed_events)
        
        # Sütunları düzenle (Gereksiz verileri gizle, adli bilişim formatına sok)
        istenen_sutunlar = ["date", "time", "event_id", "event_type", "user", "ip", "hostname", "process", "source", "status", "risk", "score", "detection", "record_id"]
        mevcut_sutunlar = [col for col in istenen_sutunlar if col in df.columns]
        df = df[mevcut_sutunlar]

        if "Excel" in secim:
            path, _ = QFileDialog.getSaveFileName(self, "Kaydet", "Rapor.xlsx", "Excel (*.xlsx)")
            if path:
                with pd.ExcelWriter(path, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, sheet_name='LogRaporu')
                    worksheet = writer.sheets['LogRaporu']
                    for col in worksheet.columns:
                        max_len = max(len(str(cell.value or '')) for cell in col)
                        col_letter = openpyxl.utils.get_column_letter(col[0].column)
                        worksheet.column_dimensions[col_letter].width = max(max_len + 4, 15)
                QMessageBox.information(self, "Başarılı", f"Excel raporu ({len(self.analyzed_events)} olay) başarıyla kaydedildi.")

        elif "CSV" in secim:
            path, _ = QFileDialog.getSaveFileName(self, "Kaydet", "Rapor.csv", "CSV (*.csv)")
            if path:
                df.to_csv(path, index=False, sep=';', encoding='utf-8-sig')
                QMessageBox.information(self, "Başarılı", f"CSV raporu ({len(self.analyzed_events)} olay) başarıyla kaydedildi.")

        elif "JSON" in secim:
            path, _ = QFileDialog.getSaveFileName(self, "Kaydet", "Rapor.json", "JSON (*.json)")
            if path:
                # JSON içine yazarken datetime objesi hata vermesin diye stringe çeviriyoruz
                json_events = []
                for ev in self.analyzed_events:
                    ev_copy = ev.copy()
                    if 'datetime' in ev_copy and isinstance(ev_copy['datetime'], datetime):
                        ev_copy['datetime'] = ev_copy['datetime'].isoformat()
                    json_events.append(ev_copy)
                
                with open(path, 'w', encoding='utf-8') as jf:
                    json.dump(json_events, jf, ensure_ascii=False, indent=4)
                QMessageBox.information(self, "Başarılı", f"JSON raporu ({len(self.analyzed_events)} olay) başarıyla kaydedildi.")

    def closeEvent(self, event):
        """Uygulama kapatılırken arka plan işçilerini güvenle sonlandırır."""
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.stop_worker_safely(self.worker)
        if hasattr(self, 'live_worker') and self.live_worker.isRunning():
            self.stop_worker_safely(self.live_worker)
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())