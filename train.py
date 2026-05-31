import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from xgboost import XGBClassifier
import pickle

# ================================
# 1. Load Dataset
# ================================
df = pd.read_csv('dataset/phishing.csv')

# Drop Index column
df = df.drop('Index', axis=1)

# Features aur Label alag karo
X = df.drop('class', axis=1)
y = df['class']

# Label ko 0 aur 1 mein convert karo (XGBoost k liye)
y = y.map({-1: 0, 1: 1})

print("Dataset loaded!")
print(f"Total samples: {len(df)}")
print(f"Features: {X.shape[1]}")

# ================================
# 2. Train Test Split
# ================================
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print(f"\nTraining samples: {len(X_train)}")
print(f"Testing samples: {len(X_test)}")

# ================================
# 3. Model 1 - Random Forest
# ================================
print("\n--- Training Random Forest ---")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

rf_pred = rf_model.predict(X_test)
rf_accuracy = accuracy_score(y_test, rf_pred)

print(f"Random Forest Accuracy: {rf_accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, rf_pred,
      target_names=['Legitimate', 'Phishing']))

# ================================
# 4. Model 2 - XGBoost
# ================================
print("\n--- Training XGBoost ---")
xgb_model = XGBClassifier(n_estimators=100, random_state=42,
                           eval_metric='logloss')
xgb_model.fit(X_train, y_train)

xgb_pred = xgb_model.predict(X_test)
xgb_accuracy = accuracy_score(y_test, xgb_pred)

print(f"XGBoost Accuracy: {xgb_accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, xgb_pred,
      target_names=['Legitimate', 'Phishing']))

# ================================
# 5. Models Save Karo
# ================================
print("\n--- Saving Models ---")

with open('models/random_forest.pkl', 'wb') as f:
    pickle.dump(rf_model, f)

with open('models/xgboost.pkl', 'wb') as f:
    pickle.dump(xgb_model, f)

print("✅ random_forest.pkl saved!")
print("✅ xgboost.pkl saved!")
print("\n🎉 Training Complete!")