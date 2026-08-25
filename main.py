import sys
import os
import csv
import json
from collections import Counter 
import xml.etree.ElementTree as ET
import subprocess

import Evtx.Evtx as evtx

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, 
                               QHBoxLayout, QGridLayout, QWidget, QTableWidget, QTableWidgetItem, 
                               QFileDialog, QLabel, QGroupBox, QMessageBox, QAbstractItemView,
                               QComboBox, QLineEdit, QInputDialog) 
from PySide6.QtGui import QColor, QFont

# Tıklanabilir Dashboard kutucukları için sınıf
class ClickableLabel(QLabel):
    clicked = Signal()
    def mousePressEvent(self, event):
        self.clicked.emit()

from PySide6.QtCore import QThread, Signal

class LogWorker(QThread):
    log_ready = Signal(list, int)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, file_path, ioc_mode, known_malicious_ips, vt_api_key):
        super().__init__()
        self.file_path = file_path
        self.ioc_mode = ioc_mode
        self.known_malicious_ips = known_malicious_ips
        self.vt_api_key = vt_api_key

    def run(self):
        try:
            logs = []
            if self.file_path.endswith('.csv'):
                import csv
                with open(self.file_path, "r", encoding="utf-8") as file:
                    reader = csv.reader(file)
                    next(reader, None) 
                    logs = list(reader)
                    for idx, log in enumerate(logs):
                        self.log_ready.emit(log, idx)
                        self.msleep(15) # Akış hissi için minik gecikme
            elif self.file_path.endswith('.evtx'):
                logs = self.parse_evtx_stream(self.file_path)
            
            self.finished.emit(logs)
        except Exception as e:
            self.error.emit(str(e))

    def parse_evtx_stream(self, file_path):
        logs = []
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
        try:
            with evtx.Evtx(file_path) as evtx_file:
                for idx, record in enumerate(evtx_file.records()):
                    root = ET.fromstring(record.xml())
                    system = root.find(f'{ns}System')
                    event_data = root.find(f'{ns}EventData')
                    if system is None: continue
                    event_id_elem = system.find(f'{ns}EventID')
                    event_id = event_id_elem.text if event_id_elem is not None else ""
                    time_elem = system.find(f'{ns}TimeCreated')
                    saat = ""
                    if time_elem is not None:
                        raw_time = time_elem.get('SystemTime', '')
                        if "T" in raw_time:
                            saat = raw_time.split("T")[1].split(".")[0][:5] 
                    kullanici, ip, durum = "System", "-", "Bilgi"
                    if event_data is not None:
                        for data in event_data.findall(f'{ns}Data'):
                            name = data.get('Name')
                            val = data.text or ""
                            if name in ['TargetUserName', 'SubjectUserName'] and val and val != "SYSTEM":
                                kullanici = val
                            elif name == 'IpAddress' and val and val != "-":
                                ip = val
                            elif name == 'NewProcessName':
                                durum = val.split("\\")[-1] 
                    
                    log_row = [saat, event_id, kullanici, ip, durum]
                    logs.append(log_row)
                    self.log_ready.emit(log_row, idx)
        except Exception as e:
            print(f"EVTX ayrıştırma hatası: {e}")
        return logs

class MainWindow(QMainWindow):
    def add_single_log_row_live(self, log, row_idx):
        if len(log) < 5: return
        saat, event_id, kullanici, ip, durum = log
        
        risk_skoru = 0
        tespit = "Normal Aktivite"
        if "Administrator" in kullanici and event_id == "4672":
            risk_skoru += 5
            tespit = "Kural 3: Şüpheli Yönetici Yetkisi Ataması"
        elif event_id == "4688" and "cmd.exe" in durum:
            risk_skoru += 10
            tespit = "Kural 4: Şüpheli İşlem"
        elif event_id == "4625":
            risk_skoru += 1
            tespit = "Kural 2: Başarısız Giriş"

        known_malicious_ips = ["185.15.15.15", "45.33.32.156", "10.0.0.99", "185.220.101.5"]
        if ip in known_malicious_ips:
            risk_skoru += 50
            tespit = "🚨 IOC MATCH DETECTED (Zارarlı IP Tespiti)"

        yazi_rengi = QColor(0, 0, 0)
        kalin_yazi = False
        if "IOC MATCH" in tespit:
            risk_seviyesi = "☠️ FATAL"
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

        self.log_table.insertRow(row_idx)
        satir_verileri = [saat, event_id, kullanici, ip, durum, risk_seviyesi, tespit]
        for col_idx, data in enumerate(satir_verileri):
            hucre = QTableWidgetItem(data)
            hucre.setBackground(renk)
            hucre.setForeground(yazi_rengi)
            if kalin_yazi:
                kalin_font = QFont()
                kalin_font.setBold(True)
                hucre.setFont(kalin_font)
            self.log_table.setItem(row_idx, col_idx, hucre)

    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("WinLogSentinel - Security Log Analyzer (Ultimate Edition)")
        self.resize(1100, 750) 
        
        ekran = QApplication.primaryScreen().availableGeometry()
        x = (ekran.width() - self.width()) // 2
        y = (ekran.height() - self.height()) // 2
        self.move(x, y)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. DASHBOARD PANELİ (HEPSİ İNTERAKTİF)
        self.dashboard_group = QGroupBox("📊 Güvenlik Dashboard (Detaylar için metinlere tıklayabilirsiniz)")
        dashboard_layout = QGridLayout() 

        self.lbl_total = ClickableLabel("Toplam Olay: 0")
        self.lbl_critical = ClickableLabel("🔴 Kritik Olay: 0")
        self.lbl_risk_dist = ClickableLabel("📊 Risk Dağılımı: 🟢 Low | 🟡 Medium | 🟠 High | 🔴 Critical | ☠️ Fatal")
        
        self.lbl_top_ip = ClickableLabel("🌐 En Aktif IP: -")
        self.lbl_top_user = ClickableLabel("👤 En Aktif Kullanıcı: -")
        self.lbl_top_event_id = ClickableLabel("🆔 En Sık Event ID: -")

        # Tıklanma aksiyonları (Hızlı Filtreleme)
        self.lbl_total.clicked.connect(lambda: self.clear_filter())
        self.lbl_critical.clicked.connect(lambda: self.quick_filter("Risk Seviyesi", "Critical"))
        self.lbl_risk_dist.clicked.connect(self.select_risk_level_dialog) # Risk dağılımı için açılır menü
        self.lbl_top_ip.clicked.connect(lambda: self.filter_by_label_text(self.lbl_top_ip, "IP Adresi", "En Aktif IP: "))
        self.lbl_top_user.clicked.connect(lambda: self.filter_by_label_text(self.lbl_top_user, "Kullanıcı", "En Aktif Kullanıcı: "))
        self.lbl_top_event_id.clicked.connect(lambda: self.filter_by_label_text(self.lbl_top_event_id, "Event ID", "En Sık Event ID: "))

        font = QFont()
        font.setBold(True)
        font.setPointSize(11)

        labels = [self.lbl_total, self.lbl_critical, self.lbl_risk_dist, 
                  self.lbl_top_ip, self.lbl_top_user, self.lbl_top_event_id]
        
        for lbl in labels:
            lbl.setFont(font)
            if isinstance(lbl, ClickableLabel):
                lbl.setStyleSheet("color: #4a90e2; text-decoration: underline; cursor: pointer;")
            
        dashboard_layout.addWidget(self.lbl_total, 0, 0)
        dashboard_layout.addWidget(self.lbl_critical, 0, 1)
        dashboard_layout.addWidget(self.lbl_risk_dist, 0, 2)
        
        dashboard_layout.addWidget(self.lbl_top_ip, 1, 0)
        dashboard_layout.addWidget(self.lbl_top_user, 1, 1)
        dashboard_layout.addWidget(self.lbl_top_event_id, 1, 2)

        self.dashboard_group.setLayout(dashboard_layout)
        main_layout.addWidget(self.dashboard_group) 

        # 2. BUTONLAR
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
        
        # --- YENİ EKLENEN BUTON BURADA ---
        self.btn_manage_blocks = QPushButton("🛡️ Güvenlik Duvarı & Whitelist")
        self.btn_manage_blocks.setMinimumHeight(40)
        self.btn_manage_blocks.clicked.connect(self.show_blocked_ips_manager)
        button_layout.addWidget(self.btn_manage_blocks)
        # ---------------------------------
        
        main_layout.addLayout(button_layout)

        # 2.5 IOC MOD SEÇİMİ (Yerel vs VirusTotal)
        ioc_layout = QHBoxLayout()
        ioc_layout.addWidget(QLabel("🛡️ IOC Tehdit İstihbarat Modu:"))
        self.combo_ioc_mode = QComboBox()
        self.combo_ioc_mode.addItems(["Yerel Veritabanı (Offline)", "VirusTotal Canlı Sorgu (Online)"])
        self.combo_ioc_mode.setMinimumHeight(30)
        ioc_layout.addWidget(self.combo_ioc_mode)
        main_layout.addLayout(ioc_layout)

        # 3. FİLTRELEME
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filtrele:"))
        self.filter_column = QComboBox()
        self.filter_column.addItems(["Tümü", "Saat", "Event ID", "Kullanıcı", "IP Adresi", "Durum", "Risk Seviyesi", "Tespit Nedeni"])
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

        # 4. TABLO
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(7)
        self.log_table.setHorizontalHeaderLabels(["Saat", "Event ID", "Kullanıcı", "IP Adresi", "Durum", "Risk Seviyesi", "Tespit Nedeni"])
        self.log_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        main_layout.addWidget(self.log_table)
        self.log_table.cellDoubleClicked.connect(self.show_event_details)
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check_file_update)
        self.current_file = None
        self.last_mod_time = 0
        self.last_log_count = 0 

    # --- AKILLI FİLTRELEME FONKSİYONLARI ---
    def quick_filter(self, column, value):
        self.filter_column.setCurrentText(column)
        self.filter_input.setText(value)
        self.apply_filter()

    def filter_by_label_text(self, label, column_name, prefix_text):
        text = label.text()
        if ":" in text:
            val = text.split(":", 1)[1].strip()
            if val and val != "-":
                self.quick_filter(column_name, val)

    def select_risk_level_dialog(self):
        risk_seviyeleri = ["Low", "Medium", "High", "Critical", "Fatal"]
        secim, ok = QInputDialog.getItem(self, "Risk Seviyesi Seç", "Filtrelemek istediğiniz risk seviyesini seçin:", risk_seviyeleri, 0, False)
        if ok and secim:
            self.quick_filter("Risk Seviyesi", secim)

    def load_log_file(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.stop_analysis_worker()
            return

        # 1. Önce dosya seçme penceresini açıyoruz (pencere hemen kapanacak)
        file_path, _ = QFileDialog.getOpenFileName(self, "Log Dosyası Seç", "", "Desteklenen Loglar (*.csv *.evtx);;CSV Files (*.csv);;EVTX Files (*.evtx)")
        
        # 2. Eğer kullanıcı dosya seçtiyse devam ediyoruz
        if file_path:
            append_mode = False
            
            # 3. Dosya seçildikten SONRA tabloda veri var mı diye soruyoruz
            if self.log_table.rowCount() > 0:
                cevap = QMessageBox.question(
                    self, 
                    "Log Birleştirme Modu", 
                    "Tabloda halihazırda yüklenmiş loglar var.\n\nYeni yüklenen dosyayı mevcut logların **üzerine mi eklemek** istiyorsunuz, yoksa **tabloyu temizleyip yenisini mi** getirmek istiyorsunuz?\n\n(Evet = Üzerine Ekle, Hayır = Temizle ve Başla)",
                    QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                    QMessageBox.Yes
                )
                
                if cevap == QMessageBox.Cancel:
                    return
                elif cevap == QMessageBox.Yes:
                    append_mode = True 
                else:
                    append_mode = False 

            self.current_file = file_path
            self.last_mod_time = os.path.getmtime(file_path)
            self.btn_export.setEnabled(True)
            self.btn_live.setEnabled(True)
            self.last_log_count = 0 

            self.process_file(file_path, show_popup=True, is_live_update=False, append=append_mode)

    def process_file(self, file_path, show_popup=False, is_live_update=False, append=False):
        ioc_mode = self.combo_ioc_mode.currentText() if hasattr(self, 'combo_ioc_mode') else "Yerel"
        known_malicious_ips = ["185.15.15.15", "45.33.32.156", "10.0.0.99", "185.220.101.5"]
        vt_api_key = "3573d24e8fb924cc5180ed5655b31717aa405f6f86c2e2e295b217050a67b7e1"

        self.btn_load_log.setText("⏹️ Akışı Durdur (İptal Et)")
        self.btn_load_log.setStyleSheet("background-color: #d32f2f; color: white; font-weight: bold;")
        
        try:
            self.btn_load_log.clicked.disconnect()
        except RuntimeError:
            pass
        self.btn_load_log.clicked.connect(self.stop_analysis_worker)
        
        if not append:
            self.log_table.setRowCount(0)

        self.worker = LogWorker(file_path, ioc_mode, known_malicious_ips, vt_api_key)
        self.worker.log_ready.connect(self.add_single_log_row_live)
        self.worker.finished.connect(lambda logs: self.on_analysis_finished(logs, show_popup, is_live_update))
        self.worker.error.connect(self.on_analysis_error)
        self.worker.start()

    def add_single_log_row_live(self, log, row_idx):
        if len(log) < 5: return
        saat, event_id, kullanici, ip, durum = log
        target_row = self.log_table.rowCount()
        
        risk_skoru = 0
        tespit = "Normal Aktivite"
        
        if "Administrator" in str(kullanici) and str(event_id) == "4672":
            risk_skoru += 5
            tespit = "Kural 3: Şüpheli Yönetici Yetkisi Ataması"
        elif str(event_id) == "4688" and "cmd.exe" in str(durum):
            risk_skoru += 16
            tespit = "Kural 4: Şüpheli İşlem"
        elif str(event_id) == "4625":
            risk_skoru += 1
            tespit = "Kural 2: Başarısız Giriş"

        known_malicious_ips = ["185.15.15.15", "45.33.32.156", "10.0.0.99", "185.220.101.5"]
        if str(ip).strip() in known_malicious_ips:
            risk_skoru += 50
            tespit = "🚨 IOC MATCH DETECTED (Zararlı IP Tespiti)"

        yazi_rengi = QColor(0, 0, 0)
        kalin_yazi = False
        
        # --- BEYAZ LİSTE KONTROLLÜ RENK VE ENGELLEME ---
        if "IOC MATCH" in tespit or risk_skoru >= 20:
            risk_seviyesi = "☠️ FATAL"
            if hasattr(self, "risk_counts"): self.risk_counts["Fatal"] += 1
            if hasattr(self, "critical_events"): self.critical_events += 1
            renk = QColor(0, 0, 0)
            yazi_rengi = QColor(255, 255, 255)
            kalin_yazi = True
            
            # YENİ: Beyaz Liste (Whitelist) Kontrolü
            if hasattr(self, 'block_ip_in_firewall') and ip and ip != "-":
                beyaz_liste = getattr(self, 'unblocked_ips', set())
                if ip in beyaz_liste:
                    tespit += " [✅ İZİN VERİLDİ - Pas geçildi]"
                else:
                    self.block_ip_in_firewall(ip, sessiz_mod=True)
                    tespit += " [⛔ OTO-ENGELLENDİ]"
                    
        elif risk_skoru == 0:
            risk_seviyesi = "🟢 Low"
            if hasattr(self, "risk_counts"): self.risk_counts["Low"] += 1
            renk = QColor(100, 255, 100)
        elif 1 <= risk_skoru <= 4:
            risk_seviyesi = "🟡 Medium"
            if hasattr(self, "risk_counts"): self.risk_counts["Medium"] += 1
            renk = QColor(255, 255, 100)
        elif 5 <= risk_skoru <= 15:
            risk_seviyesi = "🟠 High"
            if hasattr(self, "risk_counts"): self.risk_counts["High"] += 1
            renk = QColor(255, 165, 0)
        else:
            risk_seviyesi = "🔴 Critical"
            if hasattr(self, "risk_counts"): self.risk_counts["Critical"] += 1
            if hasattr(self, "critical_events"): self.critical_events += 1
            renk = QColor(255, 50, 50)
            yazi_rengi = QColor(255, 255, 255)
            kalin_yazi = True

        self.log_table.insertRow(target_row)
        satir_verileri = [saat, event_id, kullanici, ip, durum, risk_seviyesi, tespit]
        
        for col_idx, data in enumerate(satir_verileri):
            hucre = QTableWidgetItem(str(data))
            hucre.setBackground(renk)
            hucre.setForeground(yazi_rengi)
            if kalin_yazi:
                kalin_font = QFont()
                kalin_font.setBold(True)
                hucre.setFont(kalin_font)
            self.log_table.setItem(target_row, col_idx, hucre)
            
        if hasattr(self, 'total_events'):
            self.total_events += 1
            if hasattr(self, 'update_live_dashboard'):
                self.update_live_dashboard()
                
    def stop_analysis_worker(self):
        if hasattr(self, 'worker') and self.worker.isRunning():
            self.worker.terminate()
            self.worker.wait()
        
        self.reset_load_button()
        QMessageBox.information(self, "İptal Edildi", "Log analizi ve canlı akış kullanıcı tarafından durduruldu.")

    def reset_load_button(self):
        self.btn_load_log.setText("📁 Log Dosyası Yükle (.csv / .evtx)")
        self.btn_load_log.setStyleSheet("")
        try:
            self.btn_load_log.clicked.disconnect()
        except RuntimeError:
            pass
        # Butonu tekrar normal dosya yükleme fonksiyonuna bağlıyoruz
        self.btn_load_log.clicked.connect(self.load_log_file)
        self.btn_load_log.setEnabled(True)

    def on_analysis_finished(self, logs, show_popup, is_live_update):
        self.reset_load_button()
        self.log_table.resizeColumnsToContents()
        
        # Canlı akış zaten satırları eklediği için analyze_and_display ile tekrar ekletmiyoruz,
        # sadece toplam log sayısını güncelliyoruz.
        self.last_log_count = len(logs)
        
        # Eğer istersen sadece dashboard üstündeki toplam sayaçları güncelleyen bir fonksiyon çağırabilirsin
        # Örn: self.update_dashboard_counters(logs)
        
    def on_analysis_error(self, err_msg):
        self.reset_load_button()
        QMessageBox.warning(self, "Okuma Hatası", f"Dosya işlenirken hata oluştu:\n{err_msg}")

    def parse_evtx(self, file_path):
        logs = []
        ns = '{http://schemas.microsoft.com/win/2004/08/events/event}'
        try:
            with evtx.Evtx(file_path) as evtx_file:
                for record in evtx_file.records():
                    root = ET.fromstring(record.xml())
                    system = root.find(f'{ns}System')
                    event_data = root.find(f'{ns}EventData')
                    if system is None: continue
                    event_id_elem = system.find(f'{ns}EventID')
                    event_id = event_id_elem.text if event_id_elem is not None else ""
                    time_elem = system.find(f'{ns}TimeCreated')
                    saat = ""
                    if time_elem is not None:
                        raw_time = time_elem.get('SystemTime', '')
                        if "T" in raw_time:
                            saat = raw_time.split("T")[1].split(".")[0][:5] 
                    kullanici, ip, durum = "System", "-", "Bilgi"
                    if event_data is not None:
                        for data in event_data.findall(f'{ns}Data'):
                            name = data.get('Name')
                            val = data.text or ""
                            if name in ['TargetUserName', 'SubjectUserName'] and val and val != "SYSTEM":
                                kullanici = val
                            elif name == 'IpAddress' and val and val != "-":
                                ip = val
                            elif name == 'NewProcessName':
                                durum = val.split("\\")[-1] 
                    logs.append([saat, event_id, kullanici, ip, durum])
        except Exception as e:
            print(f"EVTX ayrıştırma hatası: {e}")
        return logs

    def toggle_live_sync(self):
        if self.timer.isActive():
            self.timer.stop()
            self.btn_live.setText("▶️ Canlı İzlemeyi Başlat (Live Sync)")
            self.btn_live.setStyleSheet("")
            
            # Kapatıldığında çıkan uyarı penceresi
            uyari = QMessageBox(self)
            uyari.setWindowTitle("Live Sync Durduruldu")
            uyari.setIcon(QMessageBox.Warning)
            uyari.setText("Canlı izleme sonlandırıldı. Log dosyası artık arka planda dinlenmiyor.")
            
            ekran = QApplication.primaryScreen().availableGeometry()
            x = (ekran.width() - 400) // 2
            y = (ekran.height() - 200) // 2
            uyari.move(x, y)
            uyari.exec()
        else:
            self.timer.start(2000) 
            self.btn_live.setText("⏹ Canlı İzleme Aktif (Sistem Dinleniyor...)")
            self.btn_live.setStyleSheet("background-color: #2e7d32; color: white; font-weight: bold;")
            
            # Açıldığında çıkan uyarı penceresi
            uyari = QMessageBox(self)
            uyari.setWindowTitle("Live Sync Aktif")
            uyari.setIcon(QMessageBox.Information)
            uyari.setText("Canlı izleme başlatıldı. Log dosyasına yeni bir kayıt düştüğünde tablo otomatik olarak güncellenecektir.")
            
            ekran = QApplication.primaryScreen().availableGeometry()
            x = (ekran.width() - 400) // 2
            y = (ekran.height() - 200) // 2
            uyari.move(x, y)
            uyari.exec()

    def check_file_update(self):
        if self.current_file and os.path.exists(self.current_file):
            current_mod_time = os.path.getmtime(self.current_file)
            if current_mod_time > self.last_mod_time:
                self.last_mod_time = current_mod_time
                self.process_file(self.current_file, show_popup=True, is_live_update=True)

    def analyze_and_display(self, logs, show_popup=True, is_live_update=False):
        failed_attempts_by_ip = {}
        user_event_history = {} 
        
        # 1. Kullanıcının Arayüzden Seçtiği IOC Modunu Al
        ioc_mode = self.combo_ioc_mode.currentText() if hasattr(self, 'combo_ioc_mode') else "Yerel"
        known_malicious_ips = ["185.15.15.15", "45.33.32.156", "10.0.0.99"]
        
        def check_virustotal_api(ip_address):
            import requests
            API_KEY = "3573d24e8fb924cc5180ed5655b31717aa405f6f86c2e2e295b217050a67b7e1"
            
            try:
                print(f"[🌐] VirusTotal API'ye canlı sorgu atılıyor: {ip_address}...")
                headers = {"x-apikey": API_KEY}
                url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
                response = requests.get(url, headers=headers, timeout=3)
                
                print(f"[🌐] VirusTotal Yanıt Kodu: {response.status_code}")
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious_count = stats.get("malicious", 0)
                    print(f"[🌐] VT Analiz Sonucu -> Zararlı Sayısı: {malicious_count}")
                    if malicious_count > 0:
                        return True
            except Exception as e:
                print(f"[!] VT Bağlantı Hatası: {e}")
                pass
                
            return ip_address in known_malicious_ips # Hata veya temiz çıkma durumunda yerel listeye fallback yapar
        
        ioc_detected = False
        new_ioc_found = False 
        ioc_details = [] 
        total_events = len(logs)
        critical_events = 0
        all_ips = []
        all_users = []
        all_event_ids = []
        risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0, "Fatal": 0}
        
        for row_idx, log in enumerate(logs):
            if len(log) < 5: continue 
            saat, event_id, kullanici, ip, durum = log
            all_ips.append(ip)
            all_users.append(kullanici)
            all_event_ids.append(event_id)
            if kullanici not in user_event_history:
                user_event_history[kullanici] = []
            user_event_history[kullanici].append(event_id)
            
            risk_skoru = 0
            tespit = "Normal Aktivite"
            if "Administrator" in kullanici and event_id == "4672":
                risk_skoru += 5
                tespit = "Kural 3: Şüpheli Yönetici Yetkisi Ataması"
            if event_id == "4688" and "cmd.exe" in durum:
                risk_skoru += 10
                tespit = "Kural 4: Şüpheli İşlem (Zararlı Parent Process)"
            saat_dilimi = int(saat.split(":")[0]) if ":" in saat else 12
            if event_id == "4624" and (saat_dilimi < 6):
                risk_skoru += 5
                tespit = "Kural 5: Mesai Dışı Beklenmeyen Giriş"
            if event_id == "4625":
                risk_skoru += 1
                failed_attempts_by_ip[ip] = failed_attempts_by_ip.get(ip, 0) + 1
                deneme_sayisi = failed_attempts_by_ip[ip]
                if deneme_sayisi >= 3: 
                    risk_skoru += 20
                    tespit = f"Kural 1: Brute Force İhtimali ({deneme_sayisi}. Deneme)"
                else:
                    tespit = "Kural 2: Başarısız Giriş"
            
            # IOC Kontrolü (Moda göre Yerel veya Online)
            is_malicious = False
            if "VirusTotal" in ioc_mode:
                is_malicious = check_virustotal_api(ip)
            else:
                is_malicious = (ip in known_malicious_ips)

            if is_malicious:
                risk_skoru += 50 
                tespit = "🚨 IOC MATCH DETECTED (Zararlı IP Tespiti)"
                ioc_detected = True
                if is_live_update:
                    if row_idx >= self.last_log_count:
                        ioc_details.append(f"<span style='color:red; font-size:14px;'>🔴 <b>[YENİ SIZMA]</b> IP: {ip} &nbsp;&nbsp;(Satır: {row_idx + 1})</span>")
                        new_ioc_found = True
                    else:
                        ioc_details.append(f"<span style='color:gray;'>⚪ [Önceki Kayıt] IP: {ip} &nbsp;&nbsp;(Satır: {row_idx + 1})</span>")
                else:
                    ioc_details.append(f"🔴 IP: {ip} &nbsp;&nbsp;(Satır: {row_idx + 1})")
                    new_ioc_found = True

            if event_id == "4672":
                gecmis = user_event_history[kullanici]
                if "4625" in gecmis and "4624" in gecmis:
                    risk_skoru += 30
                    tespit = "🚨 Olay Korelasyonu: Possible Account Compromise! (Fail -> Success -> Admin)"
            
            yazi_rengi = QColor(0, 0, 0)
            kalin_yazi = False
            if "IOC MATCH" in tespit:
                risk_seviyesi = "☠️ FATAL"
                risk_counts["Fatal"] += 1 
                critical_events += 1
                renk = QColor(0, 0, 0) 
                yazi_rengi = QColor(255, 255, 255) 
                kalin_yazi = True
            elif risk_skoru == 0:
                risk_seviyesi = "🟢 Low"
                risk_counts["Low"] += 1
                renk = QColor(100, 255, 100) 
            elif 1 <= risk_skoru <= 4:
                risk_seviyesi = "🟡 Medium"
                risk_counts["Medium"] += 1
                renk = QColor(255, 255, 100) 
            elif 5 <= risk_skoru <= 15:
                risk_seviyesi = "🟠 High"
                risk_counts["High"] += 1
                renk = QColor(255, 165, 0) 
            else:
                risk_seviyesi = "🔴 Critical"
                risk_counts["Critical"] += 1
                critical_events += 1
                renk = QColor(255, 50, 50) 
            
            self.log_table.insertRow(row_idx)
            satir_verileri = [saat, event_id, kullanici, ip, durum, risk_seviyesi, tespit]
            for col_idx, data in enumerate(satir_verileri):
                hucre = QTableWidgetItem(data)
                hucre.setBackground(renk)
                hucre.setForeground(yazi_rengi)
                if kalin_yazi:
                    kalin_font = QFont()
                    kalin_font.setBold(True)
                    hucre.setFont(kalin_font)
                self.log_table.setItem(row_idx, col_idx, hucre)
        
        self.log_table.resizeColumnsToContents()
        self.lbl_total.setText(f"Toplam Olay: {total_events}")
        self.lbl_critical.setText(f"🔴 Kritik Olay: {critical_events}")
        dist_text = f"📊 Risk Dağılımı: 🟢 {risk_counts['Low']} | 🟡 {risk_counts['Medium']} | 🟠 {risk_counts['High']} | 🔴 {risk_counts['Critical']} | ☠️ {risk_counts['Fatal']}"
        self.lbl_risk_dist.setText(dist_text)
        
        if all_ips:
            en_cok_ip = Counter(all_ips).most_common(1)[0][0]
            self.lbl_top_ip.setText(f"🌐 En Aktif IP: {en_cok_ip}")
        if all_users:
            en_cok_user = Counter(all_users).most_common(1)[0][0]
            self.lbl_top_user.setText(f"👤 En Aktif Kullanıcı: {en_cok_user}")
        if all_event_ids:
            en_cok_event = Counter(all_event_ids).most_common(1)[0][0]
            self.lbl_top_event_id.setText(f"🆔 En Sık Event ID: {en_cok_event}")
            
        if ioc_detected and show_popup and new_ioc_found:
            html_kayitlar = "<br>".join(ioc_details)
            html_mesaj = f"<h3>DİKKAT! Log dosyasında bilinen zararlı IP adresleri (IOC) tespit edildi!</h3><b>Bulunan Kayıtlar:</b><br><br>{html_kayitlar}<br><br><i>Lütfen tablodaki ilgili satırları inceleyin ve derhal ağ bağlantısını kesin.</i>"
            uyari = QMessageBox(self)
            uyari.setWindowTitle("🚨 KRİTİK GÜVENLİK UYARISI")
            uyari.setIcon(QMessageBox.Critical)
            uyari.setText(html_mesaj)
            ekran = QApplication.primaryScreen().availableGeometry()
            x = (ekran.width() - 400) // 2
            y = (ekran.height() - 200) // 2
            uyari.move(x, y)
            uyari.exec()

    def apply_filter(self):
        search_text = self.filter_input.text().lower() 
        selected_column = self.filter_column.currentText()
        column_map = {"Saat": 0, "Event ID": 1, "Kullanıcı": 2, "IP Adresi": 3, "Durum": 4, "Risk Seviyesi": 5, "Tespit Nedeni": 6}
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
                if item and search_text in item.text().lower():
                    match = True
            self.log_table.setRowHidden(row, not match)

    def clear_filter(self):
        self.filter_input.clear()
        self.filter_column.setCurrentIndex(0) 
        for row in range(self.log_table.rowCount()):
            self.log_table.setRowHidden(row, False)

    def block_ip_in_firewall(self, ip_address, sessiz_mod=False):
        if not ip_address or ip_address == "-": return
        
        rule_name = f"WinLogSentinel_Block_{ip_address}"
        komut = f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=block remoteip={ip_address}'
        
        try:
            import subprocess
            # Komutu çalıştır
            subprocess.run(komut, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Eğer kullanıcı butona basarak engellediyse mesaj ver, sistem kendi engellediyse sessiz kal
            if not sessiz_mod:
                QMessageBox.information(self, "Başarılı", f"⛔ {ip_address} IP adresi Windows Firewall üzerinden başarıyla engellendi!")
        except subprocess.CalledProcessError:
            # Eğer yetki yoksa sadece manuel işlemlerde hata ver (akışı bölmemek için)
            if not sessiz_mod:
                QMessageBox.critical(self, "Yetki Hatası", "Güvenlik duvarı kuralı eklenemedi!\n\nLütfen WinLogSentinel programını (veya VS Code'u) 'Yönetici Olarak Çalıştır' seçeneğiyle açıp tekrar deneyin.")

    def show_blocked_ips_manager(self):
        import subprocess
        
        if not hasattr(self, 'unblocked_ips'):
            self.unblocked_ips = set()
            
        # 1. Hangi listeyi görüntülemek istediğini sor
        modlar = [
            "⛔ Engellenen IP'leri Listele (Engeli Kaldır)",
            "✅ Beyaz Listedeki (İzin Verilen) IP'leri Listele / Yönet"
        ]
        secilen_mod, ok = QInputDialog.getItem(
            self, 
            "🛡️ IP Yönetim Paneli", 
            "İşlem yapmak istediğiniz kategoriyi seçin:", 
            modlar, 0, False
        )
        if not ok or not secilen_mod:
            return

        # --- A. ENGELLENEN IP'LER MODU ---
        if "⛔ Engellenen" in secilen_mod:
            komut = 'netsh advfirewall firewall show rule name=all'
            engellenenler = []
            
            try:
                result = subprocess.run(komut, shell=True, capture_output=True, text=True, encoding='cp857')
                for line in result.stdout.splitlines():
                    if "WinLogSentinel_Block_" in line:
                        parts = line.split("WinLogSentinel_Block_")
                        if len(parts) > 1:
                            ip = parts[1].strip()
                            if ip not in engellenenler:
                                engellenenler.append(ip)
            except Exception as e:
                print(f"Okuma hatası: {e}")
            
            if not engellenenler:
                QMessageBox.information(self, "Bilgi", "Şu anda güvenlik duvarında engellenmiş bir IP adresi bulunmuyor.")
                return
                
            secilen_ip, ok = QInputDialog.getItem(
                self, 
                "⛔ Engellenen IP Listesi", 
                "Engelini kaldırıp 'Beyaz Liste'ye almak istediğiniz IP'yi seçin:", 
                engellenenler, 0, False
            )
            
            if ok and secilen_ip:
                kural_adi = f"WinLogSentinel_Block_{secilen_ip}"
                sil_komut = f'netsh advfirewall firewall delete rule name="{kural_adi}"'
                try:
                    subprocess.run(sil_komut, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    self.unblocked_ips.add(secilen_ip)
                    QMessageBox.information(
                        self, 
                        "Başarılı", 
                        f"✅ {secilen_ip} IP adresinin engeli kaldırıldı ve Beyaz Liste'ye eklendi!"
                    )
                except subprocess.CalledProcessError:
                    QMessageBox.critical(self, "Yetki Hatası", "Engel kaldırılamadı!\n\nLütfen programı Yönetici olarak çalıştırın.")

        # --- B. BEYAZ LİSTE (İZİN VERİLENLER) MODU ---
        else:
            if not self.unblocked_ips:
                QMessageBox.information(self, "Bilgi", "Şu anda Beyaz Liste'de (İzin Verilen) kayıtlı bir IP adresi bulunmuyor.")
                return
                
            beyaz_liste_dizi = list(self.unblocked_ips)
            secilen_ip, ok = QInputDialog.getItem(
                self, 
                "✅ Beyaz Liste (İzin Verilenler)", 
                "Beyaz listeden ÇIKARMAK (Tekrar tespit edildiğinde engellenebilir yapmak) istediğiniz IP'yi seçin:\n\n(İşlem yapmadan çıkmak için İptal'e basabilirsiniz)", 
                beyaz_liste_dizi, 0, False
            )
            
            if ok and secilen_ip:
                self.unblocked_ips.remove(secilen_ip)
                QMessageBox.information(
                    self, 
                    "Güncellendi", 
                    f"ℹ️ {secilen_ip} IP adresi Beyaz Liste'den çıkarıldı.\n\nBir sonraki analizde zararlı olarak gelirse tekrar otomatik olarak engellenecektir."
                )

    def show_event_details(self, row, column):
        saat = self.log_table.item(row, 0).text()
        event_id = self.log_table.item(row, 1).text()
        kullanici = self.log_table.item(row, 2).text()
        ip = self.log_table.item(row, 3).text()
        durum = self.log_table.item(row, 4).text()
        risk = self.log_table.item(row, 5).text()
        tespit = self.log_table.item(row, 6).text()

        onerilen_aksiyon = "Normal bir aktivite, özel bir işleme gerek yoktur."
        gerekli_mudahale = False 

        if "IOC MATCH" in tespit: 
            onerilen_aksiyon = f"KRİTİK DURUM! {ip} adresi bilinen zararlılar listesindedir. Ağ bağlantısı derhal kesilmelidir!"
            gerekli_mudahale = True
        elif "Brute Force" in tespit: 
            onerilen_aksiyon = f"Acil Durum! {ip} IP adresi derhal Firewall üzerinden engellenmelidir."
            gerekli_mudahale = True
        elif "Şüpheli İşlem" in tespit: 
            onerilen_aksiyon = f"Zararlı Yazılım İhtimali! İlgili bilgisayarda antivirüs taraması yapılmalıdır."
        elif "Yetkisi Ataması" in tespit:
            onerilen_aksiyon = f"Yetki Yükseltme! {kullanici} kullanıcısına verilen admin yetkisinin onayı kontrol edilmelidir."
        elif "Başarısız Giriş" in tespit:
            onerilen_aksiyon = f"{ip} adresinden gelen giriş denemeleri izlenmeye devam edilmelidir."
        elif "Mesai Dışı" in tespit:
            onerilen_aksiyon = f"Şüpheli Giriş! {kullanici} kullanıcısının bu saatte çalışıp çalışmadığı teyit edilmelidir."
        elif "Account Compromise" in tespit:
            onerilen_aksiyon = f"İHLAL TESPİTİ! {kullanici} kullanıcısının hesabı ele geçirilmiş olabilir. Acil parola sıfırlama işlemi gereklidir."

        detay_mesaji = f"Risk Seviyesi: {risk}\nTarih / Saat: {saat}\nKullanıcı: {kullanici}\nIP Adresi: {ip}\nEvent ID: {event_id}\n\n📋 Tespit Nedeni:\n{tespit}\n\n🔍 İşlem Durumu:\n{durum}\n\n💡 Önerilen Aksiyon:\n{onerilen_aksiyon}"
        
        uyari = QMessageBox(self)
        uyari.setWindowTitle("Güvenlik Uyarısı Detayı")
        uyari.setIcon(QMessageBox.Information)
        uyari.setText(detay_mesaji)
        
        # Standart "Tamam" butonu
        ok_btn = uyari.addButton(QMessageBox.Ok)
        
        # Eğer zararlı bir IP varsa "Engelle" butonu ekle
        block_btn = None
        if gerekli_mudahale and ip and ip != "-":
            block_btn = uyari.addButton("⛔ Bu IP'yi Firewall'dan Engelle", QMessageBox.ActionRole)
            
        uyari.exec()

        # Eğer kullanıcı engelle butonuna bastıysa fonksiyonu çağır
        if block_btn and uyari.clickedButton() == block_btn:
            self.block_ip_in_firewall(ip)

    def export_report(self):
        import json
        import csv
        import os
        from datetime import datetime
        
        formatlar = ["CSV (Excel Uyumlu Tablo)", "JSON (Detaylı Özet ve Yapılandırılmış Metin)"]
        secim, ok = QInputDialog.getItem(self, "Rapor Formatı Seç", "Lütfen kaydetmek istediğiniz formatı seçin:", formatlar, 0, False)
        if not ok: return

        current_time = datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        
        risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0, "Fatal": 0}
        suspicious_count = 0
        events = []
        
        headers = [self.log_table.horizontalHeaderItem(c).text() for c in range(self.log_table.columnCount())]
        
        # SADECE EKRANDA GÖRÜNEN (FİLTRELENMEMİŞ) SATIRLARI ALIYORUZ
        visible_row_count = 0
        for row in range(self.log_table.rowCount()):
            if self.log_table.isRowHidden(row): 
                continue 
                
            visible_row_count += 1
            row_data = {}
            for c in range(self.log_table.columnCount()):
                item = self.log_table.item(row, c)
                val = item.text() if item else ""
                row_data[headers[c]] = val
                
                # Özet istatistikler için risk sayımı
                if c == 5: 
                    if "Low" in val: risk_counts["Low"] += 1
                    elif "Medium" in val: risk_counts["Medium"] += 1
                    elif "High" in val: 
                        risk_counts["High"] += 1
                        suspicious_count += 1
                    elif "Critical" in val: 
                        risk_counts["Critical"] += 1
                        suspicious_count += 1
                    elif "FATAL" in val or "Fatal" in val: 
                        risk_counts["Fatal"] += 1
                        suspicious_count += 1

            events.append(row_data)

        summary = {
            "Analiz_Tarihi": current_time,
            "Disa_Aktarilan_Kayit_Sayisi": visible_row_count,
            "Supheli_Olay_Sayisi": suspicious_count,
            "Risk_Dagilimi": f"Low: {risk_counts['Low']}, Medium: {risk_counts['Medium']}, High: {risk_counts['High']}, Critical: {risk_counts['Critical']}, Fatal: {risk_counts['Fatal']}"
        }

        # 1. CSV KAYIT
        if "CSV" in secim:
            file_path, _ = QFileDialog.getSaveFileName(self, "CSV Raporunu Kaydet", "Guvenlik_Analiz_Raporu.csv", "CSV Files (*.csv)")
            if file_path:
                try:
                    with open(file_path, "w", newline="", encoding="utf-8-sig") as file:
                        writer = csv.writer(file, delimiter=';')
                        writer.writerow(headers)
                        for row_data in events:
                            # Emojileri temizleyip temiz bir kurumsal Excel formatı sunuyoruz
                            temiz_veri = [row_data.get(h, "").replace("🟢 ", "").replace("🟡 ", "").replace("🟠 ", "").replace("🔴 ", "").replace("☠️ ", "") for h in headers]
                            writer.writerow(temiz_veri)
                    QMessageBox.information(self, "Başarılı", f"CSV Raporu ekrandaki {visible_row_count} kayıt ile başarıyla kaydedildi.")
                except PermissionError:
                    # EĞER EXCEL AÇIKSA UYARI VER!
                    QMessageBox.critical(self, "Erişim Engellendi!", "Dosya şu anda Excel'de veya başka bir programda AÇIK!\n\nLütfen açık olan Excel dosyasını kapatıp tekrar 'İndir' butonuna basın veya kaydederken farklı bir isim verin (Örn: Rapor_Yeni.csv).")
                
        # 2. JSON KAYIT
        else:
            file_path, _ = QFileDialog.getSaveFileName(self, "JSON Raporunu Kaydet", "Guvenlik_Analiz_Raporu.json", "JSON Files (*.json)")
            if file_path:
                report_data_final = {
                    "Rapor_Ozeti": summary,
                    "Tespit_Edilen_Olaylar": events
                }
                
                # Emojileri temizleme
                for ev in report_data_final["Tespit_Edilen_Olaylar"]:
                    if "Risk Seviyesi" in ev:
                        ev["Risk Seviyesi"] = ev["Risk Seviyesi"].replace("🟢 ", "").replace("🟡 ", "").replace("🟠 ", "").replace("🔴 ", "").replace("☠️ ", "")
                        
                try:
                    with open(file_path, "w", encoding="utf-8") as f:
                        json.dump(report_data_final, f, ensure_ascii=False, indent=4)
                    QMessageBox.information(self, "Başarılı", f"JSON Raporu ekrandaki {visible_row_count} kayıt ile başarıyla kaydedildi.")
                except PermissionError:
                    QMessageBox.critical(self, "Erişim Engellendi!", "Dosya şu anda başka bir programda AÇIK!\n\nLütfen dosyayı kapatıp tekrar deneyin.")
                    
if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())