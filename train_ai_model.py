import os
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

# Ensure models directory exists
MODEL_DIR = "models"
os.makedirs(MODEL_DIR, exist_ok=True)

# Sample dataset (Replace with actual network threat dataset)
data = {
    "src_port": [443, 80, 22, 53, 445, 3389, 25, 8080, 21, 3306],
    "dst_port": [443, 80, 22, 53, 445, 3389, 25, 8080, 21, 3306],
    "protocol": [6, 6, 6, 17, 6, 6, 6, 6, 6, 6],  # TCP=6, UDP=17
    "packet_size": [500, 700, 200, 300, 1500, 2000, 400, 900, 250, 1800],
    "risk_level": [0, 1, 2, 1, 3, 3, 2, 1, 2, 3]  # 0=Safe, 1=Suspicious, 2=Risky, 3=Dangerous
}

# Convert data to DataFrame
df = pd.DataFrame(data)

# Features and labels
X = df.drop("risk_level", axis=1)
y = df["risk_level"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate model
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.2f}")
print(classification_report(y_test, y_pred))

# Save model
model_path = os.path.join(MODEL_DIR, "ai_threat_model.pkl")
with open(model_path, "wb") as f:
    pickle.dump(model, f)

print(f"Model saved to {model_path}")
