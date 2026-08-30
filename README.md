# 🛡️ WinLogSentinel - Security Log Analyzer & IPS (Ultimate Edition)

WinLogSentinel, Windows sistemlerinden elde edilen güvenlik loglarını hem statik dosyalardan (`.evtx` ve `.csv`) hem de doğrudan Windows işletim sisteminin canlı RAM akışından (`wevtutil` entegrasyonu ile) derinlemesine analiz eden, yapay zeka destekli anomali tespiti yapabilen ve kritik tehditlere karşı otomatik aksiyon (`IPS/SOAR`) alabilen profesyonel bir masaüstü siber güvenlik analitiği aracıdır.

## 🚀 Proje Hakkında

Bu proje, bir güvenlik uzmanının ham log dosyalarını tek tek incelemesi yerine; bu kayıtları asenkron olarak ayrıştıran, skorlayan ve şık bir arayüzle sunan gelişmiş bir sistemdir. İçerdiği **Detection Engine (Tespit Motoru)**, **Isolation Forest Yapay Zeka Modeli** ve **Canlı wevtutil Windows RAM Dinleme Motoru** sayesinde sadece imza tabanlı tehditleri değil, alışılmadık saatlerdeki davranış anomalilerini de anlık olarak yakalar. Tespit ettiği zararlı IP'leri Windows Firewall üzerinden anında otomatik olarak engeller.

---

## ✨ Öne Çıkan Özellikler ve Savunma Yetenekleri

* **⚡ Canlı Windows RAM Motoru (wevtutil Entegrasyonu):** Statik dosyaların aksine, Windows işletim sisteminin tampon bellek kısıtlamalarını bypass ederek en güncel güvenlik olaylarını saniyesinde yakalar.
* **🤖 Yapay Zeka Destekli Anomali Tespiti (IsolationForest):** Normal dışı saatlerde gerçekleşen oturum açma aktivitelerini makine öğrenmesi modelleriyle analiz ederek sıfırıncı gün (*zero-day*) davranış anomalilerini yakalar.
* **🔥 Tam Otomatik Olay Müdahalesi (IPS/SOAR):** Sistem, FATAL (Kritik Zararlı) seviyesindeki bir IP'yi tespit ettiği milisaniye içerisinde Windows Defender Firewall'a müdahale ederek saldırganın ağ bağlantısını otomatik olarak keser (*Drop*).
* **🎯 Manuel Tehdit Avcılığı & Whitelist:** Log tablosunda şüpheli görülen bir IP adresine çift tıklayarak anında manuel engelleme yapabilir; güvenilir IP'leri Beyaz Liste'ye (*Whitelist*) ekleyerek yanlış alarmların önüne geçebilirsiniz.
* **📊 İnteraktif SOC Dashboard'u:** Toplam olay, risk dağılımı, en aktif IP ve kullanıcı istatistiklerini anlık görselleştirir. Mavi metinlere tıklayarak hızlı filtreleme yapılabilir.
* **📜 Denetim Kaydı (Audit Log):** Sistemden engeli kaldırılan tüm IP adresleri, tarih ve saat bilgisiyle birlikte adli bilişim standartlarına uygun olarak `denetim_kaydi.txt` dosyasına kayıt altına alınır.

---

## 🛠️ Kullanılan Teknolojiler

* **Gelişmiş Dil:** Python 3.x
* **Arayüz (GUI):** PySide6 (Asenkron `QThread` destekli modern mimari)
* **Yapay Zeka (AI):** Scikit-Learn (`IsolationForest` tabanlı anomali motoru)
* **Log Ayrıştırma:** `python-evtx` ve Windows `wevtutil` API subprocess entegrasyonu
* **Sistem Entegrasyonu:** subprocess (`Windows Firewall netsh` API kontrolü)
* **Veri İşleme:** pandas, openpyxl, requests, numpy, yerleşik `csv`, `json` ve `datetime` modülleri.

---

## ⚙️ Kurulum ve Çalıştırma

Projeyi kendi bilgisayarınızda çalıştırmak için şu adımları izleyebilirsiniz:

1. **Depoyu bilgisayarınıza indirin (Clone):**
   ```bash
   git clone [https://github.com/beyza-gunel/WinLogSentinel.git](https://github.com/beyza-gunel/WinLogSentinel.git)
   cd WinLogSentinel
2. Gerekli Python kütüphanelerini kurun:
   ```bash
   pip install PySide6 python-evtx scikit-learn requests numpy pandas openpyxl 
3. YÖNETİCİ İZNİ (ÖNEMLİ):
   Firewall engelleme, kural yönetimi ve canlı wevtutil RAM sorgularının tam çalışabilmesi için uygulamanızı veya terminalinizi Yönetici Olarak (Run as Administrator) başlatın:
   ```bash
   python main.py   

---

## 🚨 Tespit Kuralları ve Yapay Zeka Modeli
Uygulama arka planda hem imza tabanlı kuralları hem de yapay zekayı koşturarak 5 farklı risk seviyesinde (Low, Medium, High, Critical, Fatal) skorlama yapar:

* Rule 1 (Brute Force İhtimali): Aynı IP/kullanıcıdan kısa süre içinde 3 ve daha fazla başarısız giriş denemesi (Critical / Fatal).

* Rule 2 (Başarısız Giriş): Event ID 4625 içeren olağan dışı başarısız parola denemeleri (Medium).

* Rule 3 (Şüpheli Yönetici Aktivitesi): "Administrator" kullanıcısına özel yetki ataması - Event ID 4672 (High).

* Rule 4 (Şüpheli İşlem - Process): Command Prompt (cmd.exe) gibi potansiyel zararlı script çalıştırabilecek processlerin başlatılması - Event ID 4688 (Critical).

* 🧠 AI Anomali Tespiti: Isolation Forest algoritması ile kullanıcının alışılmadık saatlerde gerçekleştirdiği oturum açma hareketlerinin yakalanması (Fatal).   

---

📌 Raporlama ve Dışa Aktarım
Analiz edilen ve filtrelenen logları CSV (özel noktalı virgül formatı) veya JSON (yapılandırılmış detaylı özet) formatında tek tıkla bilgisayarınıza indirebilirsiniz.

Geliştirici: Beyza Günel