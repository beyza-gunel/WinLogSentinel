# 🛡️ WinLogSentinel - Security Log Analyzer

**WinLogSentinel**, Windows sistemlerinden elde edilen güvenlik loglarını analiz ederek şüpheli aktiviteleri tespit eden, risk seviyesini belirleyen ve sonuçları kullanıcıya raporlayan masaüstü tabanlı bir siber güvenlik aracıdır.

## 🚀 Proje Hakkında
Bu proje, bir güvenlik uzmanının ham log dosyalarını tek tek incelemesi yerine; bu kayıtları otomatik olarak ayrıştıran (parse), analiz eden, skorlayan ve şık bir arayüzle sunan bir **MVP (Minimum Viable Product)** olarak tasarlanmıştır.

## 🛠️ Kullanılan Teknolojiler
* **Geliştirme Dili:** Python 3
* **Arayüz (GUI) Kütüphanesi:** PySide6
* **Veri İşleme ve Çıktı:** Yerleşik `csv` ve `json` kütüphaneleri

## ⚙️ Kurulum ve Çalıştırma
Projeyi kendi bilgisayarınızda çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

1. Depoyu bilgisayarınıza indirin (Clone).
2. Gerekli arayüz kütüphanesini kurun:
   `pip install PySide6`
3. Proje dizininde terminali açarak uygulamayı başlatın:
   `python main.py`

## 🔍 Kullanım
1. Uygulama açıldığında **"Log Dosyası Yükle ve Analiz Et"** butonuna tıklayarak (örneğin `test_logs.csv` dosyasını) sisteme yükleyin.
2. Üst paneldeki **Güvenlik Dashboard'u** üzerinden toplam, kritik olay sayılarını ve risk dağılımını anlık inceleyin.
3. Tablo üzerindeki herhangi bir olaya **çift tıklayarak** olay detaylarını ve "Önerilen Aksiyon" penceresini görüntüleyin.
4. İşleminiz bittiğinde **"Analiz Raporunu İndir"** butonunu kullanarak sonuçları CSV veya JSON formatında dışa aktarın.

## 🚨 Tespit Kuralları (Detection Rules)
Uygulama arka planda şu kuralları çalıştırarak risk analizi yapar:

* **Rule 1 (Brute Force İhtimali):** Aynı IP'den kısa süre içinde 3 ve daha fazla başarısız giriş yapılması. (Kritik)
* **Rule 2 (Başarısız Giriş):** Event ID 4625 içeren olağan dışı başarısız parola denemeleri.
* **Rule 3 (Şüpheli Yönetici Aktivitesi):** "Administrator" kullanıcısına özel yetki ataması yapılması (Event ID 4672).
* **Rule 4 (Şüpheli İşlem - Process):** Command Prompt (`cmd.exe`) gibi potansiyel zararlı script çalıştırabilecek processlerin başlatılması (Event ID 4688).
* **Rule 5 (Mesai Dışı Beklenmeyen Giriş):** Saat 00:00 ile 06:00 arasında gerçekleşen başarılı girişler (Event ID 4624).

## ⚠️ Bilinen Eksiklikler ve Gelecek Geliştirmeler
* Şu an için sadece yapılandırılmış `.csv` formatındaki logları okumaktadır. Gelecek sürümlerde doğrudan `.evtx` (Windows Event Log) dosyalarını parse edecek bir modül eklenecektir.
* IOC (Indicator of Compromise) mekanizması için dış IP itibar (Reputation) API'leri ile entegrasyon planlanmaktadır.