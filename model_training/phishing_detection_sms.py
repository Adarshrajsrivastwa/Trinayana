import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

# === Step 1: Load Dataset ===
df = pd.read_csv("phishing_SMS_dataset.csv", encoding='ISO-8859-1')
print("📄 Columns:", df.columns.tolist())
print("📊 Sample:\n", df.head())

# === Step 2: Standardize Column Names ===
if df.shape[1] >= 2:
    df.columns = ['label', 'message'] + list(df.columns[2:])

# === Step 3: Clean & Encode Labels ===
df.fillna('', inplace=True)
df['label'] = df['label'].map({'ham': 0, 'spam': 1})  # 0 = Legitimate, 1 = Phishing

# === Step 4: Extract Features via TF-IDF ===
vectorizer = TfidfVectorizer(max_features=2000)
X = vectorizer.fit_transform(df['message'])
y = df['label']

# === Step 5: Split Dataset ===
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# === Step 6: Train Random Forest ===
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# === Step 7: Evaluate Model ===
y_pred = model.predict(X_test)
print("✅ Accuracy:", accuracy_score(y_test, y_pred))
print("📊 Classification Report:\n", classification_report(y_test, y_pred))

# === Step 8: Single Prediction Function ===
def predict_sms(text):
    features = vectorizer.transform([text])
    prediction = model.predict(features)[0]
    return "Phishing" if prediction == 1 else "Legitimate"

# 🔹 Test Example
sample_text = "Your account is blocked. Visit bit.ly/unlock-now"
print("🔍 Prediction for sample:", sample_text)
print("➡️ Result:", predict_sms(sample_text))

# === Step 9: Save Model + Vectorizer ===
os.makedirs("../backend", exist_ok=True)
joblib.dump(model, "../backend/sms_model.pkl")
joblib.dump(vectorizer, "../backend/sms_vectorizer.pkl")
print("💾 Model and vectorizer saved to ../backend/")
