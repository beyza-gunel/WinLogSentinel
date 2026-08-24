# 🛡️ WinLogSentinel - Security Log Analyzer (Ultimate Edition)

**WinLogSentinel**, Windows sistemlerinden elde edilen güvenlik loglarını (CSV ve yerel .evtx formatlarında) analiz ederek şüpheli aktiviteleri tespit eden, risk seviyesini belirleyen ve sonuçları Siber Güvenlik Operasyon Merkezi (SOC) standartlarında kullanıcıya raporlayan interaktif bir masaüstü siber güvenlik aracıdır.

## 🚀 Proje Hakkında
Bu proje, bir güvenlik uzmanının ham log dosyalarını tek tek incelemesi yerine; bu kayıtları otomatik olarak ayrıştıran (parse), analiz eden, skorlayan ve şık bir arayüzle sunan gelişmiş bir sistem olarak tasarlanmıştır. Sistem sadece verileri listelemekle kalmaz; içerdiği **Detection Engine (Tespit Motoru)** sayesinde olaylar arasında korelasyon kurar ve analiste "Olay Detayı" paneli üzerinden Incident Response (Olay Müdahale) tavsiyeleri sunar.

## 🛠️ Kullanılan Teknolojiler
* **Geliştirme Dili:** Python 3.x
* **Arayüz (GUI) Kütüphanesi:** PySide6 (Hızlı, modern ve platform bağımsız masaüstü arayüzü geliştirmek için tercih edilmiştir.)
* **Log Ayrıştırma:** `python-evtx` (Windows'un native şifrelenmiş/sıkıştırılmış .evtx loglarını doğrudan okuyabilmek için kullanılmıştır.)
* **Veri İşleme ve Çıktı:** Yerleşik `csv`, `json` ve XML ayrıştırma için `xml.etree.ElementTree` kütüphaneleri.

## ⚙️ Kurulum ve Çalıştırma
Projeyi kendi bilgisayarınızda çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

1. Depoyu bilgisayarınıza indirin (Clone):
   ```bash
   git clone [https://github.com/beyza-gunel/WinLogSentinel.git](https://github.com/beyza-gunel/WinLogSentinel.git)
   
2. Gerekli Python kütüphanelerini kurun:
pip install PySide6 python-evtx

3. Proje dizininde terminali açarak uygulamayı başlatın:
python main.py

## 🔍 Kullanım
1. Uygulama açıldığında "Log Dosyası Yükle (.csv / .evtx)" butonuna tıklayarak (örneğin repodaki test_logs.csv dosyasını) sisteme yükleyin.

2. Üst paneldeki Güvenlik Dashboard'u üzerinden toplam, kritik olay sayılarını ve risk dağılımını anlık inceleyin. Dashboard üzerindeki mavi renkli metinlere tıklayarak hızlı filtreleme yapabilirsiniz.

3. Arka planda dosyayı dinlemek için "Canlı İzlemeyi Başlat (Live Sync)" butonunu kullanabilirsiniz.

4. Tablo üzerindeki herhangi bir olaya çift tıklayarak olay detaylarını, logun ham halini ve "Önerilen Aksiyon" penceresini görüntüleyin.

5. İşleminiz bittiğinde "Analiz Raporunu İndir" butonunu kullanarak sonuçları CSV veya JSON formatında dışa aktarın.

## 🚨 Tespit Kuralları (Detection Rules) ve Risk Skoru
Uygulama arka planda şu kuralları çalıştırarak 5 farklı risk seviyesinde (Low, Medium, High, Critical, Fatal) skorlama yapar:

* Rule 1 (Brute Force İhtimali): Aynı IP adresinden kısa süre içinde 3 ve daha fazla başarısız giriş denemesi yapılması. (Critical - Kırmızı)

* Rule 2 (Başarısız Giriş): Event ID 4625 içeren olağan dışı başarısız parola denemeleri. (Medium - Sarı)

* Rule 3 (Şüpheli Yönetici Aktivitesi): "Administrator" kullanıcısına özel yetki ataması yapılması (Event ID 4672). (Critical - Kırmızı)

* Rule 4 (Şüpheli İşlem - Process): Command Prompt (cmd.exe) gibi potansiyel zararlı script çalıştırabilecek processlerin başlatılması (Event ID 4688). (High - Turuncu)

* Rule 5 (Mesai Dışı Beklenmeyen Giriş): Saat 00:00 ile 06:00 arasında gerçekleşen başarılı/başarısız girişler. (High - Turuncu)

## 🌟 Bonus Özellikler (Gelişmiş Tehdit Tespiti)
Proje kapsamında istenen ekstra "Zor" isterler projeye başarıyla entegre edilmiştir:

* Bonus 1 (.evtx Desteği): Uygulama python-evtx kütüphanesi kullanılarak doğrudan Windows'un şifreli .evtx formatındaki loglarını parse edebilecek şekilde güncellenmiştir.

* Bonus 2 (Gerçek Zamanlı İzleme - Live Sync): Uygulama arka planda dosyayı dinler ve yeni bir kayıt/saldırı eklendiğinde tabloyu kendi kendine günceller (Aktif edildiğinde ekranda pop-up uyarı verir).

* Bonus 3 (IOC Analizi): Bilinen zararlı IP adresleri (Örn: 185.15.15.15) sisteme entegre edilmiştir. Zararlı IP giriş yaptığında sistem riskini ☠️ FATAL olarak atar. Canlı izleme sırasında yeni bir sızma olursa kırmızı fontla "YENİ SIZMA" uyarısı verir.

* Bonus 4 (Olay Korelasyonu): Bir kullanıcının sırasıyla Başarısız Giriş -> Başarılı Giriş -> Admin Yetkisi alması gibi zincirleme reaksiyonlar izlenerek "Korelasyon (Account Compromise)" tespiti yapılmaktadır.

## ⚠️ Bilinen Eksiklikler ve Gelecekte Eklenebilecek Özellikler
* Veritabanı Entegrasyonu: Şu an loglar bellek (RAM) üzerinde işlenmektedir. İlerleyen versiyonlarda Elasticsearch veya SQLite entegrasyonu ile geriye dönük milyonlarca satır log daha hızlı taranabilir.

* Otomatik Aksiyon (IPS): Uygulama şu an sadece uyarı vermekte ve analiste tavsiye sunmaktadır. Gelecekte Windows Firewall API'si ile entegre edilerek zararlı IP'leri otomatik bloklama yeteneği kazandırılabilir.

* IOC Zenginleştirmesi: IOC (Indicator of Compromise) mekanizması için dış IP itibar (Reputation) API'leri (örneğin VirusTotal) ile entegrasyon eklenebilir.