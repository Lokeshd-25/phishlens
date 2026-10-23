
import re
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix

# Load model files from the project's models folder
BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"

MODEL_PATH = MODEL_DIR / "improved_phishing_model.pkl"
TFIDF_PATH = MODEL_DIR / "tfidf_vectorizer.pkl"
SCALER_PATH = MODEL_DIR / "forensic_scaler.pkl"

model = joblib.load(MODEL_PATH)
tfidf_vectorizer = joblib.load(TFIDF_PATH)
forensic_scaler = joblib.load(SCALER_PATH)

# Cache feature names once instead of generating them per email
TEXT_FEATURE_NAMES = tfidf_vectorizer.get_feature_names_out()

FORENSIC_FEATURE_NAMES = np.array([
    "subject_length",
    "body_length",
    "word_count",
    "url_count",
    "email_count",
    "digit_count",
    "exclamation_count",
    "question_count",
    "html_tag_count",
    "uppercase_ratio",
])

ALL_FEATURE_NAMES = np.concatenate([
    TEXT_FEATURE_NAMES,
    FORENSIC_FEATURE_NAMES,
])


def analyze_email(subject, body):
    subject = "" if subject is None else str(subject)
    body = "" if body is None else str(body)

    text = subject + " " + body
    lower_text = text.lower()

    # Extract numerical forensic features
    forensic_features = pd.DataFrame([{
        "subject_length": len(subject),
        "body_length": len(body),
        "word_count": len(lower_text.split()),
        "url_count": len(re.findall(r"https?://|www\.", lower_text)),
        "email_count": len(re.findall(
            r"[\w\.-]+@[\w\.-]+\.\w+", lower_text
        )),
        "digit_count": sum(c.isdigit() for c in text),
        "exclamation_count": text.count("!"),
        "question_count": text.count("?"),
        "html_tag_count": len(re.findall(r"<[^>]+>", lower_text)),
        "uppercase_ratio": (
            sum(c.isupper() for c in text) / max(len(text), 1)
        ),
    }])

    # Convert text and scale numerical features
    tfidf_features = tfidf_vectorizer.transform([text])
    scaled_forensic = forensic_scaler.transform(forensic_features)

    combined_features = hstack([
        tfidf_features,
        csr_matrix(scaled_forensic),
    ], format="csr")

    # Predict email class and probability of class 1
 
    # Predict email class and probability of class 1
    probability = float(model.predict_proba(combined_features)[0][1])
    prediction = 1 if probability >= 0.70 else 0


    indicators = []

    if forensic_features.loc[0, "url_count"] > 0:
        indicators.append("URL present")
    if forensic_features.loc[0, "email_count"] > 0:
        indicators.append("Email address present")
    if forensic_features.loc[0, "digit_count"] >= 3:
        indicators.append("Multiple digits detected")
    if forensic_features.loc[0, "exclamation_count"] >= 2:
        indicators.append("Multiple exclamation marks")
    if forensic_features.loc[0, "question_count"] >= 2:
        indicators.append("Multiple question marks")
    if forensic_features.loc[0, "html_tag_count"] > 0:
        indicators.append("HTML content detected")
    if forensic_features.loc[0, "uppercase_ratio"] >= 0.20:
        indicators.append("High uppercase usage")
    if forensic_features.loc[0, "url_count"] == 0:
        indicators.append("No URL detected")

    # Identify up to five influential features
    model_evidence = []

    if hasattr(model, "coef_"):
        coefficients = model.coef_[0]
        row = combined_features.toarray()[0]
        contributions = row * coefficients

        if prediction == 1:
            ranked_indices = np.argsort(contributions)[::-1]
        else:
            ranked_indices = np.argsort(contributions)

        for idx in ranked_indices:
            if row[idx] != 0:
                contribution = contributions[idx]

                if (
                    (prediction == 1 and contribution > 0)
                    or (prediction == 0 and contribution < 0)
                ):
                    model_evidence.append({
                        "feature": str(ALL_FEATURE_NAMES[idx]),
                        "contribution": round(float(contribution), 4),
                    })

                if len(model_evidence) >= 5:
                    break

    # Assign risk level using class-1 probability
    if probability >= 0.80:
        risk_level = "HIGH"
    elif probability >= 0.50:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "prediction": "Phishing" if prediction == 1 else "Legitimate",
        "phishing_probability": round(probability, 4),
        "risk_level": risk_level,
        "forensic_indicators": indicators,
        "model_evidence": model_evidence,
        "forensic_features": forensic_features.iloc[0].to_dict(),
    }
