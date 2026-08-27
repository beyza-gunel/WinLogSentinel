import sys
import os
import csv
import json
import subprocess
from datetime import datetime

import xml.etree.ElementTree as ET

from PySide6.QtCore import QTimer, Qt, Signal, QThread, QCoreApplication
from PySide6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, 
                               QHBoxLayout, QGridLayout, QWidget, QTableWidget, QTableWidgetItem, 
                               QFileDialog, QLabel, QGroupBox, QMessageBox, QAbstractItemView,
                               QComboBox, QLineEdit, QInputDialog) 
from PySide6.QtGui import QColor, QFont

class ClickableLabel(QLabel):
    clicked = Signal()
    def mousePressEvent(self, event):
        self.clicked.emit()

class LogWorker(QThread):
    log_ready = Signal(list, int)
    finished = Signal(int)
    error = Signal(str)

    def __init__(self, file_path, ioc_mode, known_malicious_ips, vt_api_key, scan_mode="gecmis", last_count=0):
        super().__init__()
        self.file_path = file_path
        self.ioc_mode = ioc_mode
        self.known_malicious_ips = known_malicious_ips
        self.vt_api_key = vt_api_key
        self.scan_mode = scan_mode
        self.last_count = last_count

    def run(self):
        try:
            total_records_processed = 0
            # Eğer kullanıcı gerçek Windows Güvenlik günlüğünü seçtiyse veya canlı izlemedeysek wevtutil motorunu çalıştır
            if "Security.evtx" in self.file_path or self.scan_mode == "wevtutil_canli":
                total_records_processed = self.parse_wevtutil_live()
            else:
                # Normal dosya yüklemeleri için standart EVTX/CSV okuyucu
                if self.file_path.endswith('.csv'):
                    with open(self.file_path, "r", encoding="utf-8") as file:
                        reader = csv.reader(file)
                        next(reader, None) 
                        raw_rows = list(reader)
                        total_records_processed = len(raw_rows)
                        
                        # 🔴 DÜZELTME: raw_rows.reverse() SİLİNDİ! (Kronolojik işleme için)
                        for idx, row in enumerate(raw_rows):
                            if len(row) >= 6:
                                log_row = [row[0].strip(), row[1].strip(), row[2].strip(), row[3].strip(), row[4].strip(), row[5].strip()]
                            else:
                                continue
                            self.log_ready.emit(log_row, idx)
                else:
                    import Evtx.Evtx as evtx
                    import tempfile
                    import time
                    unique_name = f"WinLogSentinel_{int(time.time() * 1000)}.evtx"
                    temp_path = os.path.join(tempfile.gettempdir(), unique_name)
                    shutil_copied = False
                    try:
                        import shutil
                        shutil.copy2(self.file_path, temp_path)
                        shutil_copied = True
                    except Exception:
                        temp_path = self.file_path
                        
                    with evtx.Evtx(temp_path) as evtx_file:
                        all_records = list(evtx_file.records())
                        total_records_processed = len(all_records)
                        
                        if self.scan_mode == "canli_sadece":
                            self.log_ready.emit(["-", "-", "🟢 CANLI DİNLEME AKTİF", "System", "-", f"Geçmiş {total_records_processed} log yoksayıldı. Sistem dinleniyor..."], 0)
                            return total_records_processed
                            
                        records_to_process = all_records[self.last_count:total_records_processed] if self.scan_mode == "canli_guncelleme" else all_records
                        
                        # 🔴 DÜZELTME: records_to_process.reverse() SİLİNDİ! (Kronolojik işleme için)
                        
                        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
                        for idx, record in enumerate(records_to_process):
                            try:
                                root = ET.fromstring(record.xml())
                                system = root.find(f'{ns}System')
                                event_data = root.find(f'{ns}EventData')
                                if system is None: continue
                                
                                event_id = system.find(f'{ns}EventID').text if system.find(f'{ns}EventID') is not None else ""
                                raw_time = system.find(f'{ns}TimeCreated').get('SystemTime') if system.find(f'{ns}TimeCreated') is not None else ""
                                
                                tarih, saat = "-", "-"
                                if raw_time:
                                    dt_local = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone()
                                    tarih, saat = dt_local.strftime("%Y-%m-%d"), dt_local.strftime("%H:%M:%S")
                                    
                                kullanici, ip, durum = "System", "-", "Bilgi"
                                if event_data is not None:
                                    for data in event_data.findall(f'{ns}Data'):
                                        name, val = data.get('Name'), data.text or ""
                                        if name in ['TargetUserName', 'SubjectUserName'] and val and val != "SYSTEM": kullanici = val
                                        elif name in ['IpAddress', 'WorkstationName', 'SourceNetworkAddress'] and val and val != "-": ip = val
                                        elif name == 'NewProcessName': durum = val.split("\\")[-1]
                                        
                                self.log_ready.emit([tarih, saat, event_id, kullanici, ip, durum], idx)
                            except Exception:
                                continue
                                
                    if shutil_copied and os.path.exists(temp_path):
                        try: os.remove(temp_path)
                        except Exception: pass
            
            self.finished.emit(total_records_processed)
        except Exception as e:
            self.error.emit(str(e))

    def parse_wevtutil_live(self):
        logs_count = 0
        try:
            cmd = 'wevtutil qe Security /c:50 /rd:true /f:xml'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if result.returncode != 0:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='cp1254', errors='ignore')
                
            xml_output = f"<Events>{result.stdout}</Events>"
            root = ET.fromstring(xml_output)
            ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
            
            records = root.findall(f'.//{ns}Event')
            logs_count = len(records)
            
            gecici_liste = []
            for event in records:
                try:
                    system = event.find(f'{ns}System')
                    event_data = event.find(f'{ns}EventData')
                    if system is None: continue
                    
                    event_id = system.find(f'{ns}EventID').text if system.find(f'{ns}EventID') is not None else ""
                    raw_time = system.find(f'{ns}TimeCreated').get('SystemTime') if system.find(f'{ns}TimeCreated') is not None else ""
                    
                    siralama_zamani = raw_time if raw_time else "0000"
                    tarih, saat = "-", "-"
                    if raw_time:
                        dt_local = datetime.fromisoformat(raw_time.replace("Z", "+00:00")).astimezone()
                        tarih, saat = dt_local.strftime("%Y-%m-%d"), dt_local.strftime("%H:%M:%S")
                        
                    kullanici, ip, durum = "System", "-", "Bilgi"
                    if event_data is not None:
                        for data in event_data.findall(f'{ns}Data'):
                            name, val = data.get('Name'), data.text or ""
                            if name in ['TargetUserName', 'SubjectUserName'] and val and val != "SYSTEM": kullanici = val
                            elif name in ['IpAddress', 'WorkstationName', 'SourceNetworkAddress'] and val and val != "-": ip = val
                            elif name == 'NewProcessName': durum = val.split("\\")[-1]
                            
                    gecici_liste.append((siralama_zamani, [tarih, saat, event_id, kullanici, ip, durum]))
                except Exception:
                    continue
            
            # 🎯 KESİN ÇÖZÜM: Zaman damgasına (ISO time) göre EN YENİ HER ZAMAN EN ÜSTTE olacak şekilde sırala
            gecici_liste.sort(key=lambda x: x[0], reverse=False)

            for idx, item in enumerate(gecici_liste):
                self.log_ready.emit(item[1], idx)
                
        except Exception as e:
            print(f"Wevtutil hata: {e}")
            
        return logs_count

class MainWindow(QMainWindow):

    def add_single_log_row_live(self, log, row_idx):
        if len(log) < 6: return
        
        # 1️⃣ Önce log verisini değişkenlere parçalıyoruz:
        tarih, saat, event_id, kullanici, ip, durum = log
        
        # 2️⃣ Sonra log_id'yi tanımlıyoruz:
        log_id = f"{tarih}|{saat}|{event_id}|{kullanici}|{ip}|{durum}"
        
        # 3️⃣ Kontrollerimizi yapıyoruz:
        if log_id in self.seen_logs:
            return
        self.seen_logs.add(log_id)
        
        # ... tablodaki satır ekleme işlemlerin ...

        if "🟢 CANLI" in str(event_id) or "⏳ BİLGİ" in str(event_id) or "HATA" in str(event_id):
            self.log_table.insertRow(0)
            for col_idx, data in enumerate(log):
                hucre = QTableWidgetItem(str(data))
                hucre.setBackground(QColor(0, 80, 0))
                hucre.setForeground(QColor(255, 255, 255))
                font = QFont(); font.setBold(True); hucre.setFont(font)
                self.log_table.setItem(0, col_idx, hucre)
            return

        if not hasattr(self, 'failed_attempts'): self.failed_attempts = {}
        if str(event_id) == "4624": self.failed_attempts[kullanici] = 0

        risk_skoru = 0
        tespit = "Normal Aktivite"
        if "Administrator" in kullanici and str(event_id) == "4672":
            risk_skoru += 5
            tespit = "Kural 3: Şüpheli Yönetici Yetkisi Ataması"
        elif str(event_id) == "4688" and "cmd.exe" in durum:
            risk_skoru += 16
            tespit = "Kural 4: Şüpheli İşlem"
        elif str(event_id) == "4625":
            self.failed_attempts[kullanici] = self.failed_attempts.get(kullanici, 0) + 1
            deneme_sayisi = self.failed_attempts[kullanici]
            if deneme_sayisi >= 3:
                risk_skoru += 20
                tespit = f"Kural 1: Brute Force İhtimali ({deneme_sayisi}. Deneme)"
            else:
                risk_skoru += 1
                tespit = f"Kural 2: Başarısız Giriş ({deneme_sayisi}. Deneme)"

        if ip in self.known_malicious_ips:
            risk_skoru += 50
            tespit = "🚨 IOC MATCH DETECTED (Zararlı IP Tespiti)"

        yazi_rengi = QColor(0, 0, 0)
        kalin_yazi = False
        if "IOC MATCH" in tespit or risk_skoru >= 20:
            risk_seviyesi = "☠️ FATAL"
            if not hasattr(self, 'current_fatal_alerts'): self.current_fatal_alerts = []
            self.current_fatal_alerts.append(f"⏱️ {saat} | IP: {ip} - {tespit}")
            renk = QColor(0, 0, 0)
            yazi_rengi = QColor(255, 255, 255)
            kalin_yazi = True
        elif risk_skoru == 0:
            risk_seviyesi = "🟢 Low"
            renk = QColor(100, 255, 100)
        elif 1 <= risk_skoru <= 4:
            risk_seviyesi = "🟡 Medium"
            renk = QColor(255, 255, 100)
        elif 5 <= risk_skoru <= 15:
            risk_seviyesi = "🟠 High"
            renk = QColor(255, 165, 0)
        else:
            risk_seviyesi = "🔴 Critical"
            renk = QColor(255, 50, 50)
            yazi_rengi = QColor(255, 255, 255)
            kalin_yazi = True

        event_sozlugu = {
            "4624": "Başarılı Oturum Açma", "4625": "Hatalı Şifre Denemesi", "4634": "Oturum Kapatıldı",
            "4647": "Kullanıcı Çıkış Yaptı", "4672": "Özel Yetki (Admin) Kullanıldı", "4688": "Yeni Program/Komut Çalıştırıldı",
            "4720": "Yeni Hesap Açıldı", "4722": "Hesap Aktif Hale Getirildi", "4724": "Şifre Sıfırlama İşlemi",
            "4732": "Gruba Yeni Üye Eklendi", "4740": "Hesap Kilitlendi", "1102": "DİKKAT: Loglar Silindi!",
            "5379": "Kayıtlı Şifrelere Erişildi"
        }
        
        aciklama = event_sozlugu.get(str(event_id), "Standart Sistem İşlemi")
        gosterilecek_event = f"{event_id} ({aciklama})"

        # 🎯 KESİN ÇÖZÜM: Yeni gelen her log HER ZAMAN en üste (0. satıra) eklenir!
        # Arka plandaki loglar normal sıralı geldiği için sayaç 1, 2, 3 diye tertemiz sayar,
        # ekranda ise en güncel olan her zaman en tepede görünür.
        target_row = 0
        
        self.log_table.insertRow(target_row) 
        satir_verileri = [tarih, saat, gosterilecek_event, kullanici, ip, durum, risk_seviyesi, tespit]
        
        for col_idx, data in enumerate(satir_verileri):
            hucre = QTableWidgetItem(str(data))
            hucre.setBackground(renk)
            hucre.setForeground(yazi_rengi)
            if kalin_yazi:
                kalin_font = QFont(); kalin_font.setBold(True); hucre.setFont(kalin_font)
            self.log_table.setItem(target_row, col_idx, hucre) 

        if row_idx > 0 and row_idx % 200 == 0:
            QCoreApplication.processEvents()

    def __init__(self):
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

        self.lbl_total = ClickableLabel("Toplam Olay: 0")
        self.lbl_critical = ClickableLabel("🔴 Kritik Olay: 0")
        self.lbl_risk_dist = ClickableLabel("📊 Risk Dağılımı: 🟢 Low | 🟡 Medium | 🟠 High | 🔴 Critical | ☠️ Fatal")
        self.lbl_top_ip = ClickableLabel("🌐 En Aktif IP: -")
        self.lbl_top_user = ClickableLabel("👤 En Aktif Kullanıcı: -")
        self.lbl_top_event_id = ClickableLabel("🆔 En Sık Event ID: -")

        self.lbl_total.clicked.connect(lambda: self.clear_filter())
        self.lbl_critical.clicked.connect(lambda: self.quick_filter("Risk Seviyesi", "Critical"))
        self.lbl_risk_dist.clicked.connect(self.select_risk_level_dialog) 
        self.lbl_top_ip.clicked.connect(lambda: self.filter_by_label_text(self.lbl_top_ip, "IP Adresi", "En Aktif IP: "))
        self.lbl_top_user.clicked.connect(lambda: self.filter_by_label_text(self.lbl_top_user, "Kullanıcı", "En Aktif Kullanıcı: "))
        self.lbl_top_event_id.clicked.connect(lambda: self.filter_by_label_text(self.lbl_top_event_id, "Event ID", "En Sık Event ID: "))

        font = QFont(); font.setBold(True); font.setPointSize(11)
        labels = [self.lbl_total, self.lbl_critical, self.lbl_risk_dist, self.lbl_top_ip, self.lbl_top_user, self.lbl_top_event_id]
        for lbl in labels:
            lbl.setFont(font)
            lbl.setStyleSheet("color: #4a90e2; text-decoration: underline; cursor: pointer;")
            
        dashboard_layout.addWidget(self.lbl_total, 0, 0)
        dashboard_layout.addWidget(self.lbl_critical, 0, 1)
        dashboard_layout.addWidget(self.lbl_risk_dist, 0, 2)
        dashboard_layout.addWidget(self.lbl_top_ip, 1, 0)
        dashboard_layout.addWidget(self.lbl_top_user, 1, 1)
        dashboard_layout.addWidget(self.lbl_top_event_id, 1, 2)
        self.dashboard_group.setLayout(dashboard_layout)
        main_layout.addWidget(self.dashboard_group) 

        button_layout = QHBoxLayout()
        self.btn_load_log = QPushButton("📁 Log Dosyası Yükle (.csv / .evtx)")
        self.btn_load_log.setMinimumHeight(40)
        self.btn_load_log.clicked.connect(self.load_log_file)
        button_layout.addWidget(self.btn_load_log)
        
        self.btn_live = QPushButton("▶️ Canlı İzlemeyi Başlat (Live Sync)")
        self.btn_live.setMinimumHeight(40)
        self.btn_live.clicked.connect(self.toggle_live_sync)
        self.btn_live.setEnabled(False) 
        button_layout.addWidget(self.btn_live)

        self.btn_export = QPushButton("📥 Analiz Raporunu İndir")
        self.btn_export.setMinimumHeight(40)
        self.btn_export.clicked.connect(self.export_report)
        self.btn_export.setEnabled(False)
        button_layout.addWidget(self.btn_export)
        
        self.btn_manage_blocks = QPushButton("🛡️ Güvenlik Duvarı & Whitelist")
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
        self.filter_column.addItems(["Tümü", "Tarih", "Saat", "Event ID", "Kullanıcı", "IP Adresi", "Durum", "Risk Seviyesi", "Tespit Nedeni"])
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
        self.log_table.setColumnCount(8)
        self.log_table.setHorizontalHeaderLabels(["Tarih", "Saat", "Event ID", "Kullanıcı", "IP Adresi", "Durum", "Risk Seviyesi", "Tespit Nedeni"])
        self.log_table.setColumnWidth(0, 100) 
        self.log_table.setColumnWidth(1, 110) 
        self.log_table.setColumnWidth(2, 220)  
        self.log_table.setColumnWidth(3, 120) 
        self.log_table.setColumnWidth(4, 130) 
        self.log_table.setColumnWidth(5, 140) 
        self.log_table.setColumnWidth(6, 110) 
        self.log_table.horizontalHeader().resizeSection(1, 110)
        self.log_table.horizontalHeader().setMinimumSectionSize(110)
        self.log_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        main_layout.addWidget(self.log_table)
        self.log_table.cellDoubleClicked.connect(self.show_event_details)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_file_update)
        self.current_file = None
        self.last_log_count = 0 
        self.seen_logs = set()

        self.known_malicious_ips = [
            "185.15.15.15",
            "45.33.32.156",
            "10.0.0.99",
            "185.220.101.5"]

    def quick_filter(self, column, value):
        self.filter_column.setCurrentText(column)
        self.filter_input.setText(value)
        self.apply_filter()

    def filter_by_label_text(self, label, column_name, prefix_text):
        import re
        text = label.text()
        clean_text = re.sub('<[^<]+>', '', text)
        if ":" in clean_text:
            val = clean_text.split(":", 1)[1].strip()
            if val and val != "-": self.quick_filter(column_name, val)

    def select_risk_level_dialog(self):
        risk_seviyeleri = ["Low", "Medium", "High", "Critical", "Fatal"]
        secim, ok = QInputDialog.getItem(self, "Risk Seviyesi Seç", "Filtrelemek istediğiniz risk seviyesini seçin:", risk_seviyeleri, 0, False)
        if ok and secim: self.quick_filter("Risk Seviyesi", secim)

    def update_dashboard(self):
        row_count = self.log_table.rowCount()
        if row_count == 0: return
            
        risk_sayilari = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0, "FATAL": 0}
        ip_sayilari, user_sayilari, event_sayilari = {}, {}, {}

        for row in range(row_count):
            if self.log_table.isRowHidden(row): continue
            event_id = self.log_table.item(row, 2).text() if self.log_table.item(row, 2) else ""
            user = self.log_table.item(row, 3).text() if self.log_table.item(row, 3) else ""
            ip = self.log_table.item(row, 4).text() if self.log_table.item(row, 4) else ""
            risk = self.log_table.item(row, 6).text() if self.log_table.item(row, 6) else ""
            
            if "Low" in risk: risk_sayilari["Low"] += 1
            elif "Medium" in risk: risk_sayilari["Medium"] += 1
            elif "High" in risk: risk_sayilari["High"] += 1
            elif "Critical" in risk: risk_sayilari["Critical"] += 1; 
            elif "FATAL" in risk or "Fatal" in risk: risk_sayilari["FATAL"] += 1; 
                
            if ip and ip != "-": ip_sayilari[ip] = ip_sayilari.get(ip, 0) + 1
            if user and user != "-": user_sayilari[user] = user_sayilari.get(user, 0) + 1
            if event_id and event_id != "-": event_sayilari[event_id] = event_sayilari.get(event_id, 0) + 1
            
        en_aktif_ip = max(ip_sayilari, key=ip_sayilari.get) if ip_sayilari else "-"
        en_aktif_user = max(user_sayilari, key=user_sayilari.get) if user_sayilari else "-"
        en_sik_event = max(event_sayilari, key=event_sayilari.get) if event_sayilari else "-"

        self.lbl_total.setText(f'<span style="color: #66b3ff;">Toplam Olay: {row_count}</span>')
        self.lbl_top_ip.setText(f'<span style="color: #66b3ff;">🌐 En Aktif IP: {en_aktif_ip}</span>')
        self.lbl_critical.setText(f'<span style="color: #ff6666;">🔴 Kritik Olay: {risk_sayilari["Critical"] + risk_sayilari["FATAL"]}</span>')
        self.lbl_top_user.setText(f'<span style="color: #ffb74d;">👤 En Aktif Kullanıcı: {en_aktif_user}</span>')
        self.lbl_risk_dist.setText(f'📊 Risk Dağılımı: 🟢 Low: {risk_sayilari["Low"]} | 🟡 Medium: {risk_sayilari["Medium"]} | 🟠 High: {risk_sayilari["High"]} | 🔴 Critical: {risk_sayilari["Critical"]} | ☠️ Fatal: {risk_sayilari["FATAL"]}')
        self.lbl_top_event_id.setText(f'<span style="color: #b366ff;">🆔 En Sık Event ID: {en_sik_event.split(" ")[0]}</span>')

    def load_log_file(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.stop_analysis_worker()
            return

        file_path, _ = QFileDialog.getOpenFileName(self, "Log Dosyası Seç", "", "Desteklenen Loglar (*.csv *.evtx);;CSV Files (*.csv);;EVTX Files (*.evtx)")
        
        if file_path:
            scan_mode = "gecmis"
            if file_path.endswith('.evtx'):
                cevap = QMessageBox.question(
                    self, 
                    "Tarama Modu Seçimi", 
                    "Canlı Windows Güvenlik Motoru (wevtutil) kullanılsın mı?\n\n"
                    "EVET: Doğrudan Windows RAM/Canlı günlüğünden en son olayları anında çek (Önerilen)\n"
                    "HAYIR: Klasik dosya tarama modunu kullan",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                    QMessageBox.Yes
                )
                if cevap == QMessageBox.Cancel: return
                elif cevap == QMessageBox.Yes: scan_mode = "wevtutil_canli"

            self.current_file = file_path
            self.btn_export.setEnabled(True)
            self.btn_live.setEnabled(True)
            self.log_table.setRowCount(0)
            self.failed_attempts = {}
            self.current_fatal_alerts = []
            self.last_log_count = 0
            self.seen_logs.clear()
            self.process_file(file_path, show_popup=True, scan_mode=scan_mode)

    def process_file(self, file_path, show_popup=False, scan_mode="gecmis"):
        ioc_mode = self.combo_ioc_mode.currentText() if hasattr(self, 'combo_ioc_mode') else "Yerel"
        vt_api_key = "3573d24e8fb924cc5180ed5655b31717aa405f6f86c2e2e295b217050a67b7e1"

        self.btn_load_log.setText("⏹️ Akışı Durdur (İptal Et)")
        self.btn_load_log.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold;")
        
        try: self.btn_load_log.clicked.disconnect()
        except RuntimeError: pass
        self.btn_load_log.clicked.connect(self.stop_analysis_worker)
        
        self.current_fatal_alerts = [] 
        self.worker = LogWorker(file_path,ioc_mode,self.known_malicious_ips,vt_api_key,scan_mode,self.last_log_count)
        self.worker.log_ready.connect(self.add_single_log_row_live)
        self.worker.finished.connect(lambda count: self.on_analysis_finished(count, show_popup, scan_mode))
        self.worker.error.connect(self.on_analysis_error)
        self.worker.start()

    def stop_analysis_worker(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
        self.reset_load_button()
        QMessageBox.information(self, "İptal Edildi", "Log analizi durduruldu.")

    def reset_load_button(self):
        self.btn_load_log.setText("📁 Log Dosyası Yükle (.csv / .evtx)")
        self.btn_load_log.setStyleSheet("")
        try: self.btn_load_log.clicked.disconnect()
        except RuntimeError: pass
        self.btn_load_log.clicked.connect(self.load_log_file)
        self.btn_load_log.setEnabled(True)

    def on_analysis_finished(self, total_count, show_popup, scan_mode):
        self.reset_load_button()
        self.log_table.resizeColumnsToContents()
        if total_count > 0: self.last_log_count = total_count
        self.update_dashboard()
        
        if scan_mode == "wevtutil_canli" and not self.timer.isActive():
            self.toggle_live_sync() # Otomatik olarak canlı izleme döngüsünü başlatır
            
        if hasattr(self, 'current_fatal_alerts') and self.current_fatal_alerts and show_popup:
            unique_alerts = list(set(self.current_fatal_alerts))
            unique_alerts.sort(reverse=True)  # <-- İŞTE SIRALAMAYI DÜZELTEN SİHİRLİ SATIR
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

    def on_analysis_error(self, err_msg):
        self.reset_load_button()
        QMessageBox.warning(self, "Okuma Hatası", f"İşlem sırasında hata oluştu:\n{err_msg}")

    def toggle_live_sync(self):
        if self.timer.isActive():
            self.timer.stop()
            self.btn_live.setText("▶️ Canlı İzlemeyi Başlat (Live Sync)")
            self.btn_live.setStyleSheet("")
            QMessageBox.warning(self, "Live Sync Durduruldu", "Canlı izleme sonlandırıldı.")
        else:
            self.timer.start(3000) # Her 3 saniyede bir wevtutil üzerinden canlı RAM'i tarar
            self.btn_live.setText("⏹ Canlı İzleme Aktif (Sistem Dinleniyor...)")
            self.btn_live.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold;")
            QMessageBox.information(self, "Live Sync Aktif", "Canlı izleme başlatıldı. Yeni bir giriş/hata yapıldığında otomatik düşecektir.")

    def check_file_update(self):
        if hasattr(self, 'worker') and self.worker.isRunning(): return 
        if self.current_file:
            # Canlı izlemede wevtutil motorunu doğrudan tetikliyoruz
            self.process_file(self.current_file, show_popup=False, scan_mode="wevtutil_canli")

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
        "Risk Seviyesi": 6, 
        "Tespit Nedeni": 7
        }

        for row in range(self.log_table.rowCount()):
            match = False
            if selected_column == "Tümü":
                for col in range(self.log_table.columnCount()):
                    item = self.log_table.item(row, col)
                    if item and search_text in item.text().lower(): match = True; break
            else:
                col_idx = column_map[selected_column]
                item = self.log_table.item(row, col_idx)
                if item and search_text in item.text().lower(): match = True
            self.log_table.setRowHidden(row, not match)

    def clear_filter(self):
        self.filter_input.clear()
        self.filter_column.setCurrentIndex(0) 
        for row in range(self.log_table.rowCount()): self.log_table.setRowHidden(row, False)

    def block_ip_in_firewall(self, ip_address, sessiz_mod=False):
        if not ip_address or ip_address == "-": return
        rule_name = f"WinLogSentinel_Block_{ip_address}"
        kontrol_komutu = f'netsh advfirewall firewall show rule name="{rule_name}"'
        if subprocess.run(kontrol_komutu, shell=True, capture_output=True).returncode == 0: return 
        komut = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        try:
            subprocess.run(komut, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if not sessiz_mod: QMessageBox.information(self, "Başarılı", f"⛔ {ip_address} IP adresi engellendi!")
        except subprocess.CalledProcessError:
            if not sessiz_mod: QMessageBox.critical(self, "Yetki Hatası", "Yönetici olarak çalıştırdığınızdan emin olun.")

    def show_blocked_ips_manager(self):
        modlar = ["⛔ Engellenen IP'leri Listele (Engeli Kaldır)", "✅ Beyaz Liste Yönetimi"]
        secilen_mod, ok = QInputDialog.getItem(self, "🛡️ IP Yönetim Paneli", "İşlem:", modlar, 0, False)
        if not ok: return
        if "⛔ Engellenen" in secilen_mod:
            engellenenler = []
            try:
                result = subprocess.run('netsh advfirewall firewall show rule name=all', shell=True, capture_output=True, text=True, encoding='cp857', errors='ignore')
                for line in result.stdout.splitlines():
                    if "WinLogSentinel_Block_" in line:
                        ip = line.split("WinLogSentinel_Block_")[1].strip()
                        if ip not in engellenenler: engellenenler.append(ip)
            except Exception: pass
            if not engellenenler: QMessageBox.information(self, "Bilgi", "Engellenen IP yok."); return
            secilen_ip, ok = QInputDialog.getItem(self, "Engellenenler", "Engelini kaldır:", engellenenler, 0, False)
            if ok and secilen_ip:
                subprocess.run(f'netsh advfirewall firewall delete rule name="WinLogSentinel_Block_{secilen_ip}"', shell=True)
                QMessageBox.information(self, "Başarılı", f"{secilen_ip} engeli kaldırıldı.")

    def show_event_details(self, row, column):
        tarih = self.log_table.item(row, 0).text() if self.log_table.item(row, 0) else "-"
        saat = self.log_table.item(row, 1).text() if self.log_table.item(row, 1) else "-"
        event_id = self.log_table.item(row, 2).text() if self.log_table.item(row, 2) else "-"
        kullanici = self.log_table.item(row, 3).text() if self.log_table.item(row, 3) else "-"
        ip = self.log_table.item(row, 4).text() if self.log_table.item(row, 4) else "-"
        durum = self.log_table.item(row, 5).text() if self.log_table.item(row, 5) else "-"
        risk = self.log_table.item(row, 6).text() if self.log_table.item(row, 6) else "-"
        tespit = self.log_table.item(row, 7).text() if self.log_table.item(row, 7) else "-"

        detay_mesaji = f"Risk Seviyesi: {risk}\nTarih / Saat: {tarih} {saat}\nKullanıcı: {kullanici}\nIP Adresi: {ip}\nEvent ID: {event_id}\n\n📋 Tespit:\n{tespit}"
        uyari = QMessageBox(self)
        uyari.setWindowTitle("Detay")
        uyari.setText(detay_mesaji)
        uyari.exec()

    def export_report(self):
        formatlar = ["Excel (.xlsx)", "CSV (.csv)", "JSON (.json)"]
        secim, ok = QInputDialog.getItem(self, "Rapor", "Format:", formatlar, 0, False)
        if not ok: return
        
        headers = [self.log_table.horizontalHeaderItem(c).text() for c in range(self.log_table.columnCount())]
        events = []
        for row in range(self.log_table.rowCount()):
            if self.log_table.isRowHidden(row): continue 
            row_data = {headers[c]: (self.log_table.item(row, c).text() if self.log_table.item(row, c) else "") for c in range(self.log_table.columnCount())}
            events.append(row_data)
            
        if not events:
            QMessageBox.warning(self, "Uyarı", "Dışarı aktarılacak kayıt bulunamadı!")
            return

        import pandas as pd
        import openpyxl
        df = pd.DataFrame(events)

        if "Excel" in secim:
            path, _ = QFileDialog.getSaveFileName(self, "Kaydet", "Rapor.xlsx", "Excel (*.xlsx)")
            if path:
                # Pandas ile Excel'e kaydederken sütun genişliklerini otomatik ayarlıyoruz:
                with pd.ExcelWriter(path, engine='openpyxl') as writer:
                    df.to_excel(writer, index=False, sheet_name='LogRaporu')
                    worksheet = writer.sheets['LogRaporu']
                    # Tüm sütunların genişliğini içindeki metne göre otomatik ayarla (######## hatası biter!)
                    for col in worksheet.columns:
                        max_len = max(len(str(cell.value or '')) for cell in col)
                        col_letter = openpyxl.utils.get_column_letter(col[0].column)
                        worksheet.column_dimensions[col_letter].width = max(max_len + 4, 15)
                QMessageBox.information(self, "Başarılı", "Excel raporu başarıyla kaydedildi.")

        elif "CSV" in secim:
            path, _ = QFileDialog.getSaveFileName(self, "Kaydet", "Rapor.csv", "CSV (*.csv)")
            if path:
                df.to_csv(path, index=False, sep=';', encoding='utf-8-sig')
                QMessageBox.information(self, "Başarılı", "CSV raporu başarıyla kaydedildi.")

        elif "JSON" in secim:
            path, _ = QFileDialog.getSaveFileName(
        self, "Kaydet", "Rapor.json", "JSON (*.json)"
        )

        if path:
            with open(path, 'w', encoding='utf-8') as jf:
                json.dump(events, jf, ensure_ascii=False, indent=4)

        QMessageBox.information(
            self,
            "Başarılı",
            "JSON raporu başarıyla kaydedildi."
        )

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())