## 🛡️ WinLogSentinel - Security Log Analyzer & IPS (Ultimate Edition)
WinLogSentinel, Windows sistemlerinden elde edilen güvenlik loglarını hem statik dosyalardan (.evtx ve .csv) hem de doğrudan Windows işletim sisteminin canlı RAM akışından (wevtutil entegrasyonu ile) derinlemesine analiz eden, yapay zeka destekli anomali tespiti yapabilen ve kritik tehditlere karşı otomatik aksiyon (IPS/SOAR) alabilen profesyonel bir masaüstü siber güvenlik analitiği aracıdır.

## 🚀 Proje Hakkında
Bu proje, bir güvenlik uzmanının ham log dosyalarını tek tek incelemesi yerine; bu kayıtları asenkron olarak ayrıştıran, skorlayan ve şık bir arayüzle sunan gelişmiş bir sistemdir. İçerdiği Detection Engine (Tespit Motoru), Isolation Forest Yapay Zeka Modeli ve Canlı wevtutil Windows RAM Dinleme Motoru sayesinde sadece imza tabanlı tehditleri değil, alışılmadık saatlerdeki davranış anomalilerini de anlık olarak yakalar. Tespit ettiği zararlı IP'leri Windows Firewall üzerinden anında otomatik olarak engeller.

## ✨ Öne Çıkan Özellikler ve Savunma Yetenekleri (Güncel Sürüm)
⚡ Canlı Windows RAM Motoru (wevtutil Entegrasyonu): Statik dosyaların aksine, Windows işletim sisteminin tampon bellek (Active Chunk) kısıtlamalarını bypass ederek en güncel güvenlik olaylarını saniyesinde yakalar ve ekrana fırlatır.

🤖 Yapay Zeka Destekli Anomali Tespiti (IsolationForest): Normal dışı saatlerde gerçekleşen oturum açma aktivitelerini (Event ID 4624) makine öğrenmesi modelleriyle analiz ederek sıfırıncı gün (zero-day) davranış anomalilerini yakalar.

📅 Kusursuz Tarih & Saat Ayrıştırma: ISO formatındaki karmaşık zaman damgalarını anında çözer; Tarih ve Saat sütunlarını birbirinden bağımsız, kesintisiz ve simetrik bir düzende listeler.

🔥 Tam Otomatik Olay Müdahalesi (IPS/SOAR): Sistem, FATAL (Kritik Zararlı) seviyesindeki bir IP'yi tespit ettiği milisaniye içerisinde Windows Defender Firewall'a müdahale ederek saldırganın ağ bağlantısını otomatik olarak keser (Drop).

🛡️ Güvenlik Duvarı & Whitelist Yönetimi: Arayüz üzerinden tek tıkla engellenen IP'leri listeleyebilir, engelini kaldırarak Beyaz Liste'ye (Whitelist) ekleyebilir veya çıkarabilirsiniz.

📊 İnteraktif SOC Dashboard'u: Toplam olay, risk dağılımı, en aktif IP ve kullanıcı istatistiklerini anlık görselleştirir. Mavi metinlere tıklayarak hızlı filtreleme yapılabilir.

🛡️ Otomatik Savunma (IPS): Zararlı IP'leri tespit edip Windows Güvenlik Duvarı üzerinden otomatik olarak engeller.

🎯 Manuel Tehdit Avcılığı: Log tablosunda şüpheli görülen bir IP adresine çift tıklayarak anında manuel engelleme (ban) işlemi yapılabilir.

✅ Beyaz Liste (Whitelist) Yönetimi: Güvenilir IP'lerin (örn: localhost veya şirket içi IP'ler) yanlışlıkla engellenmesini önler.

📜 Denetim Kaydı (Audit Log): Sistemden engeli kaldırılan tüm IP adresleri, tarih ve saat bilgisiyle birlikte adli bilişim standartlarına uygun olarak kayıt altına alınır.

## 🛠️ Kullanılan Teknolojiler
* Geliştirme Dili: Python 3.x
* Arayüz (GUI) Kütüphanesi: PySide6 (Hızlı, modern ve asenkron QThread destekli)
* Makine Öğrenmesi (AI): Scikit-Learn (IsolationForest tabanlı anomali motoru)
* Log Ayrıştırma & Canlı Çekim: python-evtx ve Windows wevtutil API subprocess entegrasyonu
* Sistem Entegrasyonu: subprocess (Windows Firewall netsh API kontrolü)
* Veri İşleme: Yerleşik csv, json ve datetime modülleri.

## ⚙️ Kurulum ve Çalıştırma
Projeyi kendi bilgisayarınızda çalıştırmak için aşağıdaki adımları izleyebilirsiniz:

1. Depoyu bilgisayarınıza indirin (Clone):
git clone https://github.com/beyza-gunel/WinLogSentinel.git
cd WinLogSentinel

2. Gerekli Python kütüphanelerini kurun:
pip install PySide6 python-evtx scikit-learn requests numpy

3. ÖNEMLİ: Firewall engelleme, kural yönetimi ve canlı wevtutil RAM sorgularının tam çalışabilmesi için uygulamanızı veya terminalinizi Yönetici Olarak (Run as Administrator) başlatın:
python main.py

## 🚨 Tespit Kuralları (Detection Rules & AI)
Uygulama arka planda hem imza tabanlı kuralları hem de yapay zekayı koşturarak 5 farklı risk seviyesinde (Low, Medium, High, Critical, Fatal) skorlama yapar:

* Rule 1 (Brute Force İhtimali): Aynı IP/kullanıcıdan kısa süre içinde 3 ve daha fazla başarısız giriş denemesi yapılması (Critical / Fatal).
* Rule 2 (Başarısız Giriş): Event ID 4625 içeren olağan dışı başarısız parola denemeleri (Medium).
* Rule 3 (Şüpheli Yönetici Aktivitesi): "Administrator" kullanıcısına özel yetki ataması (Event ID 4672) (High).
* Rule 4 (Şüpheli İşlem - Process): Command Prompt (cmd.exe) gibi potansiyel zararlı script çalıştırabilecek processlerin başlatılması (Event ID 4688) (Critical).
* 🧠 AI Anomali Tespiti: Isolation Forest algoritması ile kullanıcının alışılmadık saatlerde gerçekleştirdiği oturum açma hareketlerinin yakalanması (Fatal).
* Olay Korelasyonu: Başarısız Giriş -> Başarılı Giriş -> Admin Yetkisi alma gibi zincirleme reaksiyonların takibi (Account Compromise).

## 1. Mantıksal Bütünlük ve Güvenlik İyileştirmeleri (UX & Path Validation)
Canlı İzleme & CSV Ayrımı: CSV gibi statik geçmiş dosyalar yüklendiğinde "Canlı İzleme" butonunun otomatik olarak pasif hale gelmesi sağlandı. Canlı dinleme özelliği yalnızca gerçek Windows Security loglarına (Security.evtx) veya anlık canlı tarama modlarına (wevtutil_canli) sınırlandırıldı.

Güvenli Dosya Yolu Kontrolü (os.path.basename): Dosya adı kontrolleri in operatörünün zafiyetlerinden arındırılarak, klasör yollarındaki yanıltıcı isimlerden etkilenmeyecek şekilde tam dosya adı eşleşmesine (os.path.basename().lower() == "security.evtx") geçirildi.

Hassas Veri Güvenliği: Kod içerisinde açıkta kalan VirusTotal API anahtarı temizlenerek kod güvenliği sağlandı.

2. Dashboard ve Filtreleme Motoru Güncellemeleri
Dinamik Dashboard Senkronizasyonu: Tabloya filtre uygulandığında (apply_filter), dashboard üzerindeki sayaçların (Toplam Olay, Kritik Olay, En Aktif IP/Kullanıcı vb.) gizlenen satırları dikkate alarak anlık ve doğru şekilde güncellenmesi sağlandı.

Kritik & Fatal Uyumsuzluğu Giderildi: Dashboard'daki "Kritik Olay" kartının hem Critical hem de FATAL seviyelerini topladığı biliniyormuş gibi, filtreleme mekanizması da "Critical" aratıldığında Fatal kayıtlarını kapsayacak şekilde akıllı hale getirildi.

Kod Temizliği (Clean Code): filter_by_label_text fonksiyonundaki gereksiz prefix_text parametresi ve ağır çalışan Regex (re) modülü kaldırılarak metin işleme mantığı sadeleştirildi ve performans artırıldı.

3. Kurumsal Tehdit İstihbaratı (IOC) Mimarisi
Harici IOC Veritabanı: Kod içerisine gömülü (hardcoded) olan zararlı IP listeleri temizlendi. Tehdit istihbaratı verileri artık dışarıdan ioc_list.json dosyası üzerinden dinamik olarak okunur hale getirildi.

Test ve Zararlı IP Ayrımı: Yerel bir private IP olan 10.0.0.99, gerçek tehdit listesinden ayrılarak test_ips adı altında güvenli bir şekilde ayrıştırıldı ve arayüz loglarında TEST IOC MATCH olarak etiketlendi.

## 📌 Raporlama ve Dışa Aktarım
Analiz edilen ve filtrelenen logları CSV (Excel uyumlu, özel noktalı virgül formatı) veya JSON (Yapılandırılmış detaylı özet) formatında tek tıkla bilgisayarınıza indirebilirsiniz.

Geliştirici: Beyza Günel