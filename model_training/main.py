
import streamlit as st
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Set page config
st.set_page_config(page_title="Phishing Detection App", layout="wide")

st.markdown("## 🔐 Phishing Detection App")
st.sidebar.header("Choose Detection Type")

option = st.sidebar.selectbox("Select input type", ["URL", "Email", "SMS"])

# ------------------ URL Detection Section --------------------
@st.cache_data
def train_url_model():
    df = pd.read_csv("Phishing_Legitimate_full.csv")

    if 'CLASS_LABEL' not in df.columns:
        st.error("Dataset missing CLASS_LABEL column.")
        return None

    X = df.drop(columns=['id', 'CLASS_LABEL'])  # Use all feature columns
    y = df['CLASS_LABEL']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    return model

# ------------------ URL UI --------------------
if option == "URL":
    st.subheader("🔗 URL Phishing Detection")
    url_input = st.text_input("Enter a URL")

    if st.button("Detect"):
        st.warning("This model is trained on extracted features, not raw URLs. Real-time prediction is not supported.")
        st.info("Please use this model with uploaded feature data only.")


# ------------------ Email Detection --------------------
@st.cache_data
def train_email_model():
    df = pd.read_csv("phishing_email_dataset.csv")
    df.fillna('', inplace=True)

    df['text'] = df['subject'] + " " + df['body'] + " " + df['sender_email']
    from sklearn.feature_extraction.text import TfidfVectorizer
    vectorizer = TfidfVectorizer(max_features=3000)

    X = vectorizer.fit_transform(df['text'])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    return model, vectorizer

def predict_email(subject, body, sender_email):
    model, vectorizer = train_email_model()
    text = subject + " " + body + " " + sender_email
    features = vectorizer.transform([text])
    prediction = model.predict(features)[0]
    return "Phishing" if prediction == 1 else "Legitimate"

# ------------------ Email UI --------------------
if option == "Email":
    st.subheader("📧 Email Phishing Detection")
    subject = st.text_input("Subject")
    body = st.text_area("Body")
    sender = st.text_input("Sender Email")

    if st.button("Detect Email"):
        result = predict_email(subject, body, sender)
        st.success(f"Prediction: {result}")


# ------------------ SMS Detection --------------------
@st.cache_data
def train_sms_model():
    df = pd.read_csv("phishing_SMS_dataset.csv", encoding="ISO-8859-1")
    df.fillna('', inplace=True)

    from sklearn.feature_extraction.text import TfidfVectorizer
    vectorizer = TfidfVectorizer(max_features=2000)
    X = vectorizer.fit_transform(df['message'])
    y = df['label']

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    return model, vectorizer

def predict_sms(text):
    model, vectorizer = train_sms_model()
    features = vectorizer.transform([text])
    prediction = model.predict(features)[0]
    return "Phishing" if prediction == 1 else "Legitimate"

# ------------------ SMS UI --------------------
if option == "SMS":
    st.subheader("📱 SMS Phishing Detection")
    sms_input = st.text_area("Enter the SMS text")

    if st.button("Detect SMS"):
        result = predict_sms(sms_input)
        st.success(f"Prediction: {result}")