# 🛡️ Phishing Website Detector

A Machine Learning based web application that detects phishing websites using URL analysis.

---

## 📌 Project Overview

This project is part of an Information Security course. It uses Machine Learning to classify websites as **Phishing** or **Legitimate** based on URL features and domain analysis.

---

## 🚀 Features

- 🔗 Real-time URL analysis
- 🤖 Random Forest ML Model (97% accuracy)
- 🌐 Flask-based Web Application
- 📊 30 URL-based features analyzed
- 🔍 WHOIS domain lookup
- ⚡ Instant prediction with confidence score

---

## 🧠 Machine Learning

| Detail | Info |
|---|---|
| Algorithm | Random Forest Classifier |
| Dataset | Phishing Website Dataset (Kaggle) |
| Total Samples | 11,054 websites |
| Features | 30 URL-based features |
| Accuracy | 96.92% |
| Train/Test Split | 80% / 20% |

---

## 📊 Features Analyzed

- IP Address in URL
- URL Length
- URL Shortener
- @ Symbol
- HTTPS Protocol
- Domain Age
- DNS Record
- Website Traffic
- Page Rank
- And 21 more...

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Python | Core Language |
| Flask | Web Framework |
| Scikit-learn | ML Model |
| Pandas & NumPy | Data Processing |
| HTML/CSS/JS | Frontend |
| WHOIS | Domain Lookup |

---

## ⚙️ Installation & Setup

```bash
# 1. Clone the repository
git clone https://github.com/mirzasaad06/phishing-detector.git

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate

# 3. Install libraries
pip install -r requirements.txt

# 4. Run the app
python app.py
```

---

## 📁 Project Structure
