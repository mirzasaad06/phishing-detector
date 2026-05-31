from flask import Flask, request, jsonify, render_template
import pickle
import numpy as np
import re
from urllib.parse import urlparse
import requests
import whois
from datetime import datetime

app = Flask(__name__)

# Sirf Random Forest load karo
with open('models/random_forest.pkl', 'rb') as f:
    rf_model = pickle.load(f)

def extract_features_from_url(url):
    features = []

    # URL ko parse karo
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith('www.'):
            domain = domain[4:]
    except:
        domain = ''

    # 1. UsingIP - URL mein IP address hai?
    ip_pattern = re.compile(r'\d+\.\d+\.\d+\.\d+')
    features.append(1 if ip_pattern.search(url) else -1)

    # 2. LongURL - URL lamba hai?
    if len(url) < 54:
        features.append(-1)
    elif len(url) <= 75:
        features.append(0)
    else:
        features.append(1)

    # 3. ShortURL - URL shortener use hua?
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'short']
    features.append(1 if any(s in url for s in shorteners) else -1)

    # 4. Symbol@ - @ symbol hai?
    features.append(1 if '@' in url else -1)

    # 5. Redirecting// - // redirect hai?
    features.append(1 if '//' in urlparse(url).path else -1)

    # 6. PrefixSuffix- - Domain mein - hai?
    features.append(1 if '-' in domain else -1)

    # 7. SubDomains - Kitne subdomains hain?
    dots = domain.count('.')
    if dots == 1:
        features.append(-1)
    elif dots == 2:
        features.append(0)
    else:
        features.append(1)

    # 8. HTTPS - HTTPS hai?
    features.append(-1 if url.startswith('https') else 1)

    # 9. DomainRegLen - Domain registration length
    try:
        w = whois.whois(domain)
        exp = w.expiration_date
        if isinstance(exp, list):
            exp = exp[0]
        reg = w.creation_date
        if isinstance(reg, list):
            reg = reg[0]
        if exp and reg:
            length = (exp - reg).days
            features.append(-1 if length >= 365 else 1)
        else:
            features.append(0)
    except:
        features.append(0)

    # 10. Favicon
    features.append(-1)

    # 11. NonStdPort - Non-standard port hai?
    port = parsed.port
    features.append(1 if port and port not in [80, 443] else -1)

    # 12. HTTPSDomainURL - HTTPS domain mein HTTP?
    features.append(1 if 'https' in domain else -1)

    # 13. RequestURL
    features.append(0)

    # 14. AnchorURL
    features.append(0)

    # 15. LinksInScriptTags
    features.append(0)

    # 16. ServerFormHandler
    features.append(0)

    # 17. InfoEmail - Email address hai?
    features.append(1 if 'mailto:' in url else -1)

    # 18. AbnormalURL - Domain URL mein hai?
    try:
        w = whois.whois(domain)
        features.append(-1 if domain in str(w.domain_name) else 1)
    except:
        features.append(0)

    # 19. WebsiteForwarding
    try:
        r = requests.get(url, timeout=5, allow_redirects=True)
        features.append(1 if len(r.history) > 2 else -1)
    except:
        features.append(0)

    # 20. StatusBarCust
    features.append(0)

    # 21. DisableRightClick
    features.append(0)

    # 22. UsingPopupWindow
    features.append(0)

    # 23. IframeRedirection
    features.append(0)

    # 24. AgeofDomain - Domain purana hai?
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age = (datetime.now() - creation).days
            features.append(-1 if age >= 180 else 1)
        else:
            features.append(0)
    except:
        features.append(0)

    # 25. DNSRecording
    try:
        w = whois.whois(domain)
        features.append(-1 if w.domain_name else 1)
    except:
        features.append(1)

    # 26. WebsiteTraffic
    features.append(0)

    # 27. PageRank
    features.append(0)

    # 28. GoogleIndex
    features.append(0)

    # 29. LinksPointingToPage
    features.append(0)

    # 30. StatsReport
    features.append(0)

    return features

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        url = data['url']

        # URL format check
        if not url.startswith('http'):
            url = 'http://' + url

        # Features extract karo
        features = extract_features_from_url(url)
        input_array = np.array([features])

        # Predict karo
        prediction = rf_model.predict(input_array)[0]
        probability = rf_model.predict_proba(input_array)[0]
        confidence = round(max(probability) * 100, 2)

        if prediction == 1:
            result = 'PHISHING'
            safe = False
        else:
            result = 'LEGITIMATE'
            safe = True

        return jsonify({
            'result': result,
            'safe': safe,
            'confidence': confidence,
            'model': 'Random Forest',
            'url': url
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True)