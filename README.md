# 🛡️ WinLogSentinel - Security Log Analyzer & IPS (Ultimate Edition)

**WinLogSentinel**, Windows sistemlerinden elde edilen güvenlik loglarını (CSV ve yerel .evtx formatlarında) analiz eden, şüpheli aktiviteleri tespit eden ve kritik tehditlere karşı **otomatik aksiyon (IPS/SOAR)** alabilen interaktif bir masaüstü siber güvenlik aracıdır.

## 🚀 Proje Hakkında
Bu proje, bir güvenlik uzmanının ham log dosyalarını tek tek incelemesi yerine; bu kayıtları otomatik olarak ayrıştıran, skorlayan ve şık bir arayüzle sunan gelişmiş bir sistemdir. Sadece verileri listelemekle kalmaz; içerdiği **Detection Engine (Tespit Motoru)** sayesinde korelasyon kurar ve zararlı IP'leri anında tespit edip ağ erişimlerini keser. Gelişmiş asenkron mimarisi (QThread) sayesinde büyük log dosyalarını arayüzü dondurmadan işler.

## ✨ Öne Çıkan Özellikler ve Savunma Yetenekleri (Yeni!)
* **🔥 Tam Otomatik Olay Müdahalesi (IPS/SOAR):** Sistem, FATAL (Kritik Zararlı) seviyesindeki bir IP'yi tespit ettiği milisaniye içerisinde Windows Defender Firewall'a müdahale ederek saldırganın ağ bağlantısını **otomatik olarak keser (Drop)**.
* **🛡️ Güvenlik Duvarı ve Whitelist Yönetimi:** Arayüz üzerinden tek tıkla engellenen IP'leri listeleyebilir, güvenli olduğunu düşündüğünüz IP'lerin engelini kaldırarak onları **Beyaz Liste'ye (Whitelist)** ekleyebilirsiniz.
* **⚡ Gerçek Zamanlı Analiz (Live Sync):** Log dosyalarını asenkron (QThread) olarak arka planda dinler. Yeni bir log düştüğünde arayüzü ve skorları anında günceller.
* **🌐 Hibrit Tehdit İstihbaratı:** Bilinen zararlı IP'ler yerel veritabanı üzerinden anlık sorgulanır.
* **📊 İnteraktif SOC Dashboard'u:** Log sayılarını, risk dağılımlarını anlık olarak görselleştirir. Mavi metinlere tıklayarak hızlı filtreleme yapılabilir.

## 🛠️ Kullanılan Teknolojiler
* **Geliştirme Dili:** Python 3.x
* **Arayüz (GUI) Kütüphanesi:** PySide6 (Hızlı, modern ve asenkron QThread destekli)
* **Log Ayrıştırma:** `python-evtx` (Şifreli/Sıkıştırılmış .evtx desteği)
* **Sistem Entegrasyonu:** `subprocess` (Windows Firewall netsh API kontrolü)
* **Veri İşleme ve Çıktı:** Yerleşik `csv` ve `json` kütüphaneleri.

## ⚙️ Kurulum ve Çalıştırma
Projeyi kendi bilgisayarınızda çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

1. Depoyu bilgisayarınıza indirin (Clone):
   ```bash
   git clone [https://github.com/beyza-gunel/WinLogSentinel.git](https://github.com/beyza-gunel/WinLogSentinel.git)
2. Gerekli Python kütüphanelerini kurun:
   ```bash
   pip install PySide6 python-evtx
3. ÖNEMLİ: Firewall engelleme özelliklerinin çalışabilmesi için uygulamayı veya terminalinizi Yönetici Olarak (Run as Administrator) başlatın:
   ```bash
   python main.py

## 🚨 Tespit Kuralları (Detection Rules)
Uygulama arka planda şu kuralları çalıştırarak 5 farklı risk seviyesinde (Low, Medium, High, Critical, Fatal) skorlama yapar:

* Rule 1 (Brute Force İhtimali): Aynı IP adresinden kısa süre içinde 3 ve daha fazla başarısız giriş denemesi yapılması. (Critical)

* Rule 2 (Başarısız Giriş): Event ID 4625 içeren olağan dışı başarısız parola denemeleri. (Medium)

* Rule 3 (Şüpheli Yönetici Aktivitesi): "Administrator" kullanıcısına özel yetki ataması (Event ID 4672). (High)

* Rule 4 (Şüpheli İşlem - Process): Command Prompt (cmd.exe) gibi potansiyel zararlı script çalıştırabilecek processlerin başlatılması (Event ID 4688). (Critical)

* Rule 5 (Mesai Dışı Beklenmeyen Giriş): Saat 00:00 ile 06:00 arasında gerçekleşen başarılı/başarısız girişler. (High)

* Rule 6 (Olay Korelasyonu): Başarısız Giriş -> Başarılı Giriş -> Admin Yetkisi alma gibi zincirleme reaksiyonların takibi (Account Compromise).

## ⚠️ Gelecekte Eklenebilecek Özellikler
* **Veritabanı Entegrasyonu:** Şu an loglar bellek (RAM) üzerinde işlenmektedir. İlerleyen versiyonlarda Elasticsearch veya SQLite entegrasyonu ile geriye dönük milyonlarca satır log daha hızlı taranabilir.
* **Makine Öğrenmesi (AI) Destekli Anomali Tespiti:** Gelecekte sisteme eklenecek bir yapay zeka modeli ile kurallara uymayan ancak şüpheli davranış sergileyen sıfırıncı gün (zero-day) saldırıları tespit edilebilir.
