# Phishing URL Tespiti - Makine Öğrenmesi Projesi

Bu proje, makine öğrenmesi tekniklerini kullanarak URL'lerin güvenli mi yoksa kimlik avı (phishing) amaçlı mı olduğunu tespit eden web tabanlı bir uygulamadır. 

## 🚀 Proje Hakkında
Proje, yaklaşık 650.000 URL içeren bir veri seti üzerinde eğitilmiş bir **XGBoost** modelini temel alır. Model, URL yapılarını, karakter dağılımlarını ve metin içeriklerini (TF-IDF) analiz ederek risk tahmini yapar.

## 🛠️ Teknolojiler
- **Backend:** Flask (Python)
- **Model:** XGBoost Classifier
- **Veri İşleme:** Pandas, NumPy, Scikit-learn
- **Frontend:** HTML, CSS, JavaScript (Glassmorphism Tasarım)

## 📁 Proje Yapısı
- `app.py`: Web arayüzünü sunan ve tahmin yapan ana uygulama.
- `train_model.py`: Veri setini işleyen ve modeli eğiten script.
- `templates/index.html`: Kullanıcı arayüzü.
- `malicious_phish.csv`: Model eğitimi için kullanılan veri seti.
- `*.pkl`: Eğitilmiş model ve yardımcı dosyalar (scaler, vectorizer vb.).

## 📊 Özellik Çıkarımı (Feature Extraction)
Model, her URL için aşağıdaki özellikleri analiz eder:
- **Yapısal Özellikler:** URL uzunluğu, nokta sayısı, özel karakter sayıları.
- **Entropi:** URL'deki karakter dağılımının karmaşıklığı.
- **IP Adresi Kontrolü:** Doğrudan IP adresi kullanımının tespiti.
- **Anahtar Kelime Analizi:** 'login', 'verify' gibi phishing sitelerinde sık geçen kelimeler.
- **TF-IDF Analizi:** Metin tabanlı karakter dizisi (n-gram) analizi.

## ⚙️ Kurulum ve Çalıştırma

1. Gerekli kütüphaneleri yükleyin:
```bash
pip install flask xgboost scikit-learn pandas joblib
```

2. Modeli eğitmek için (opsiyonel, hazır `.pkl` dosyaları mevcuttur):
```bash
python train_model.py
```

3. Uygulamayı başlatın:
```bash
python app.py
```

4. Tarayıcınızda şu adrese gidin: `http://localhost:5000`

## 🛡️ Güvenli Liste (Whitelist)
Proje; Google, GitHub, Kaggle gibi popüler ve güvenilir siteleri analiz etmeden doğrudan "Güvenli" olarak işaretleyen bir whitelist mekanizmasına sahiptir.

---
*Bu proje bir okul ödevi kapsamında geliştirilmiştir.*
