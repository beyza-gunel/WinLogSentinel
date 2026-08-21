import sys
import os
import csv
import json
from collections import Counter 
import xml.etree.ElementTree as ET

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

class MainWindow(QMainWindow):
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
        main_layout.addLayout(button_layout)

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
        file_path, _ = QFileDialog.getOpenFileName(self, "Log Dosyası Seç", "", "Desteklenen Loglar (*.csv *.evtx);;CSV Files (*.csv);;EVTX Files (*.evtx)")
        if file_path:
            self.current_file = file_path
            self.last_mod_time = os.path.getmtime(file_path)
            self.btn_export.setEnabled(True)
            self.btn_live.setEnabled(True)
            self.last_log_count = 0 
            self.process_file(file_path, show_popup=True, is_live_update=False)

    def process_file(self, file_path, show_popup=False, is_live_update=False):
        logs = []
        try:
            if file_path.endswith('.csv'):
                with open(file_path, "r", encoding="utf-8") as file:
                    reader = csv.reader(file)
                    next(reader, None) 
                    logs = list(reader)
            elif file_path.endswith('.evtx'):
                logs = self.parse_evtx(file_path)
            self.log_table.setRowCount(0)
            self.analyze_and_display(logs, show_popup, is_live_update)
            self.last_log_count = len(logs) 
        except Exception as e:
            QMessageBox.warning(self, "Okuma Hatası", f"Dosya işlenirken hata oluştu:\n{e}")

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
        known_malicious_ips = ["185.15.15.15", "45.33.32.156", "10.0.0.99"] 
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
            if ip in known_malicious_ips:
                risk_skoru += 50 
                tespit = "🚨 IOC MATCH DETECTED (Bilinen Zararlı IP)"
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

    def show_event_details(self, row, column):
        saat = self.log_table.item(row, 0).text()
        event_id = self.log_table.item(row, 1).text()
        kullanici = self.log_table.item(row, 2).text()
        ip = self.log_table.item(row, 3).text()
        durum = self.log_table.item(row, 4).text()
        risk = self.log_table.item(row, 5).text()
        tespit = self.log_table.item(row, 6).text()

        onerilen_aksiyon = "Normal bir aktivite, özel bir işleme gerek yoktur."
        if "IOC MATCH" in tespit:
            onerilen_aksiyon = f"KRİTİK DURUM! {ip} adresi bilinen zararlılar listesindedir. Ağ bağlantısı derhal kesilmelidir!"
        elif "Account Compromise" in tespit:
            onerilen_aksiyon = f"İHLAL TESPİTİ! {kullanici} kullanıcısının hesabı ele geçirilmiş olabilir. Acil parola sıfırlama işlemi gereklidir."
        elif "Brute Force" in tespit:
            onerilen_aksiyon = f"Acil Durum! {ip} IP adresi derhal Firewall üzerinden engellenmelidir."
        elif "Mesai Dışı" in tespit:
            onerilen_aksiyon = f"Şüpheli Giriş! {kullanici} kullanıcısının bu saatte çalışıp çalışmadığı teyit edilmelidir."
        elif "Şüpheli İşlem" in tespit:
            onerilen_aksiyon = f"Zararlı Yazılım İhtimali! İlgili bilgisayarda antivirüs taraması yapılmalıdır."
        elif "Yetkisi Ataması" in tespit:
            onerilen_aksiyon = f"Yetki Yükseltme! {kullanici} kullanıcısına verilen admin yetkisinin onayı kontrol edilmelidir."
        elif "Başarısız Giriş" in tespit:
            onerilen_aksiyon = f"{ip} adresinden gelen giriş denemeleri izlenmeye devam edilmelidir."

        detay_mesaji = f"""🚨 OLAY DETAYI
--------------------------------------------------
Risk Seviyesi:  {risk}
Tarih / Saat:   {saat}
Kullanıcı:      {kullanici}
IP Adresi:      {ip}
Event ID:       {event_id}

📋 Tespit Nedeni:
{tespit}

🔍 İşlem Durumu:
{durum}
--------------------------------------------------
💡 Önerilen Aksiyon:
{onerilen_aksiyon}"""
        
        uyari = QMessageBox(self)
        uyari.setWindowTitle("Güvenlik Uyarısı Detayı")
        uyari.setIcon(QMessageBox.Information)
        uyari.setText(detay_mesaji)
        
        ekran = QApplication.primaryScreen().availableGeometry()
        x = (ekran.width() - 400) // 2
        y = (ekran.height() - 200) // 2
        uyari.move(x, y)
        
        uyari.exec()

    def export_report(self):
        formatlar = ["CSV (Excel Uyumlu)", "JSON (Yapılandırılmış Metin)"]
        secim, ok = QInputDialog.getItem(self, "Rapor Formatı Seç", "Lütfen kaydetmek istediğiniz formatı seçin:", formatlar, 0, False)
        if not ok: return
            
        if "CSV" in secim:
            file_path, _ = QFileDialog.getSaveFileName(self, "CSV Raporunu Kaydet", "Guvenlik_Analiz_Raporu.csv", "CSV Files (*.csv)")
            if file_path:
                with open(file_path, "w", newline="", encoding="utf-8-sig") as file:
                    writer = csv.writer(file, delimiter=';')
                    headers = [self.log_table.horizontalHeaderItem(c).text() for c in range(self.log_table.columnCount())]
                    writer.writerow(headers)
                    for row in range(self.log_table.rowCount()):
                        row_data = [self.log_table.item(row, c).text().replace("🟢 ", "").replace("🟡 ", "").replace("🟠 ", "").replace("🔴 ", "").replace("☠️ ", "") if self.log_table.item(row, c) else "" for c in range(self.log_table.columnCount())]
                        writer.writerow(row_data)
                QMessageBox.information(self, "Başarılı", f"CSV Raporu başarıyla kaydedildi:\n{file_path}")
        else:
            file_path, _ = QFileDialog.getSaveFileName(self, "JSON Raporunu Kaydet", "Guvenlik_Analiz_Raporu.json", "JSON Files (*.json)")
            if file_path:
                report_data = []
                headers = [self.log_table.horizontalHeaderItem(c).text() for c in range(self.log_table.columnCount())]
                for row in range(self.log_table.rowCount()):
                    row_dict = {}
                    for c in range(self.log_table.columnCount()):
                        item = self.log_table.item(row, c)
                        val = item.text().replace("🟢 ", "").replace("🟡 ", "").replace("🟠 ", "").replace("🔴 ", "").replace("☠️ ", "") if item else ""
                        row_dict[headers[c]] = val
                    report_data.append(row_dict)
                with open(file_path, "w", encoding="utf-8") as f:
                    json.dump(report_data, f, ensure_ascii=False, indent=4)
                QMessageBox.information(self, "Başarılı", f"JSON Raporu başarıyla kaydedildi:\n{file_path}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())