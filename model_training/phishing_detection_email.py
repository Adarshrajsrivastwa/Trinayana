import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

# 🔹 Step 1: Load Dataset
file_path = "phishing_SMS_dataset.csv"
if not os.path.exists(file_path):
    raise FileNotFoundError(f"❌ Dataset not found at {file_path}")

df = pd.read_csv(file_path, encoding='ISO-8859-1')
print("📄 Columns:", df.columns.tolist())
print("📊 Sample Data:\n", df.head())

# 🔹 Step 2: Rename Columns
if df.shape[1] >= 2:
    df.columns = ['label', 'message'] + list(df.columns[2:])

# 🔹 Step 3: Clean & Encode
df.fillna('', inplace=True)
if df['label'].dtype == object:
    df['label'] = df['label'].map({'ham': 0, 'spam': 1})

# 🔹 Step 4: TF-IDF Feature Extraction
vectorizer = TfidfVectorizer(max_features=2000)
X = vectorizer.fit_transform(df['message'])
y = df['label']

# 🔹 Step 5: Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42)

# 🔹 Step 6: Train Random Forest Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 🔹 Step 7: Evaluation
y_pred = model.predict(X_test)
print(f"✅ Accuracy: {accuracy_score(y_test, y_pred):.4f}")
print("📈 Classification Report:\n", classification_report(y_test, y_pred))

# 🔹 Step 8: Predict Sample
def predict_sms(text):
    features = vectorizer.transform([text])
    prediction = model.predict(features)[0]
    return "Phishing" if prediction == 1 else "Legitimate"

test_message = "Your account is blocked. Visit bit.ly/unlock-now"
print("🔍 Example Prediction:", predict_sms(test_message))

# 🔹 Step 9: Save Model & Vectorizer to backend/
bos.makedirs("../backend", exist_ok=True)
joblib.dump(model, "../backend/email_model.pkl")
joblib.dump(vectorizer, "../backend/email_vectorizer.pkl")
print("💾 Model and vectorizer saved to ../backend/")
