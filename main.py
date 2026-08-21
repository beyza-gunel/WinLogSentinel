import sys
import csv
import json
from collections import Counter 
from PySide6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, 
                               QHBoxLayout, QGridLayout, QWidget, QTableWidget, QTableWidgetItem, 
                               QFileDialog, QLabel, QGroupBox, QMessageBox, QAbstractItemView,
                               QComboBox, QLineEdit, QInputDialog) 
from PySide6.QtGui import QColor, QFont

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("WinLogSentinel - Security Log Analyzer (Advanced Edition)")
        self.resize(1050, 750) 
        
        # --- PENCEREYİ EKRANIN ORTASINA HİZALAMA KODU ---
        ekran = QApplication.primaryScreen().availableGeometry()
        x = (ekran.width() - self.width()) // 2
        y = (ekran.height() - self.height()) // 2
        self.move(x, y)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. DASHBOARD PANELİ
        self.dashboard_group = QGroupBox("📊 Güvenlik Dashboard")
        dashboard_layout = QGridLayout() 

        self.lbl_total = QLabel("Toplam Olay: 0")
        self.lbl_critical = QLabel("🔴 Kritik Olay: 0")
        # GÜNCELLEME BURADA: FATAL ikonunu ekledik!
        self.lbl_risk_dist = QLabel("📊 Risk Dağılımı: 🟢 0 | 🟡 0 | 🟠 0 | 🔴 0 | ☠️ 0")
        
        self.lbl_top_ip = QLabel("🌐 En Aktif IP: -")
        self.lbl_top_user = QLabel("👤 En Aktif Kullanıcı: -")
        self.lbl_top_event_id = QLabel("🆔 En Sık Event ID: -")

        font = QFont()
        font.setBold(True)
        font.setPointSize(11)

        labels = [self.lbl_total, self.lbl_critical, self.lbl_risk_dist, 
                  self.lbl_top_ip, self.lbl_top_user, self.lbl_top_event_id]
        
        for lbl in labels:
            lbl.setFont(font)
            
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
        
        self.btn_load_log = QPushButton("📁 Log Dosyası Yükle ve Analiz Et")
        self.btn_load_log.setMinimumHeight(40)
        self.btn_load_log.clicked.connect(self.load_log_file)
        button_layout.addWidget(self.btn_load_log)

        self.btn_export = QPushButton("📥 Analiz Raporunu İndir")
        self.btn_export.setMinimumHeight(40)
        self.btn_export.clicked.connect(self.export_report)
        self.btn_export.setEnabled(False)
        button_layout.addWidget(self.btn_export)

        main_layout.addLayout(button_layout)

        # 3. FİLTRELEME ÇUBUĞU
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filtrele:"))
        
        self.filter_column = QComboBox()
        self.filter_column.addItems(["Tümü", "Saat", "Event ID", "Kullanıcı", "IP Adresi", "Durum", "Risk Seviyesi", "Tespit Nedeni"])
        filter_layout.addWidget(self.filter_column)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Aramak istediğiniz değeri yazın... (Örn: FATAL, IOC veya 4625)")
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

    def load_log_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Log Dosyası Seç", "", "CSV Files (*.csv)")
        if file_path:
            with open(file_path, "r", encoding="utf-8") as file:
                reader = csv.reader(file)
                next(reader) 
                
                self.log_table.setRowCount(0)
                logs = list(reader) 
                self.analyze_and_display(logs)
                self.btn_export.setEnabled(True)

    def analyze_and_display(self, logs):
        failed_attempts_by_ip = {}
        user_event_history = {} 
        
        known_malicious_ips = ["185.15.15.15", "45.33.32.156", "10.0.0.99"] 
        ioc_detected = False
        ioc_ips_found = set()
        
        total_events = len(logs)
        critical_events = 0
        all_ips = []
        all_users = []
        all_event_ids = []
        # GÜNCELLEME BURADA: Fatal sayacı eklendi
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
            
            # --- TEMEL KURALLAR ---
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

            # --- BONUS 3: IOC KONTROLÜ ---
            if ip in known_malicious_ips:
                risk_skoru += 50 
                tespit = "🚨 IOC MATCH DETECTED (Bilinen Zararlı IP)"
                ioc_detected = True
                ioc_ips_found.add(ip)

            # --- BONUS 4: OLAY KORELASYONU ---
            if event_id == "4672":
                gecmis = user_event_history[kullanici]
                if "4625" in gecmis and "4624" in gecmis:
                    risk_skoru += 30
                    tespit = "🚨 Olay Korelasyonu: Possible Account Compromise! (Fail -> Success -> Admin)"

            # Risk Dağılımı ve Renklendirme
            yazi_rengi = QColor(0, 0, 0)
            kalin_yazi = False
            
            # IOC İÇİN ÖZEL GÖRÜNÜM
            if "IOC MATCH" in tespit:
                risk_seviyesi = "☠️ FATAL"
                risk_counts["Fatal"] += 1 # GÜNCELLEME: Fatal sayacını artır
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

        # DASHBOARD GÜNCELLEMESİ
        self.lbl_total.setText(f"Toplam Olay: {total_events}")
        self.lbl_critical.setText(f"🔴 Kritik/Fatal Olay: {critical_events}")
        
        # GÜNCELLEME BURADA: Dashboard metnine Fatal (☠️) eklendi
        dist_text = f"📊 Risk: 🟢 {risk_counts['Low']} | 🟡 {risk_counts['Medium']} | 🟠 {risk_counts['High']} | 🔴 {risk_counts['Critical']} | ☠️ {risk_counts['Fatal']}"
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

        # --- EKRANA FIRLAYAN AKTİF ALARM ---
        if ioc_detected:
            tehlikeli_ipler = ", ".join(ioc_ips_found)
            mesaj = f"DİKKAT! Log dosyasında bilinen zararlı IP adresleri (IOC) tespit edildi!\n\nTespit Edilen IP(ler): {tehlikeli_ipler}\n\nLütfen tabloyu inceleyin ve derhal ağ bağlantısını kesin."
            QMessageBox.critical(self, "🚨 KRİTİK GÜVENLİK UYARISI", mesaj)

    def apply_filter(self):
        search_text = self.filter_input.text().lower() 
        selected_column = self.filter_column.currentText()

        column_map = {
            "Saat": 0, "Event ID": 1, "Kullanıcı": 2, "IP Adresi": 3, 
            "Durum": 4, "Risk Seviyesi": 5, "Tespit Nedeni": 6
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
        
        QMessageBox.information(self, "Güvenlik Uyarısı Detayı", detay_mesaji)

    def export_report(self):
        formatlar = ["CSV (Excel Uyumlu)", "JSON (Yapılandırılmış Metin)"]
        secim, ok = QInputDialog.getItem(self, "Rapor Formatı Seç", "Lütfen kaydetmek istediğiniz formatı seçin:", formatlar, 0, False)
        
        if not ok:
            return
            
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