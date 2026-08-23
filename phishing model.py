import pandas as pd
import sys
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib

path = "web-page-phishing.csv"
df = pd.read_csv(path)
print("Before Cleaning:", df.shape)

print("\nColumns found:", list(df.columns))


label_col = None
for col in df.columns:
    if col.lower() in ["status", "label", "class", "phishing", "target"]:
        label_col = col
        break

if label_col is None:
    sys.exit("Could not find label column. Rename target column to 'phishing' / 'label' / 'status'.")

print(f"\nUsing label column: {label_col}")

df = df.dropna(subset=[label_col])
df = df.dropna()
df = df.drop_duplicates()

print("\nUnique values in label before encoding:", df[label_col].unique())
if not set(df[label_col].unique()).issubset({0, 1}):
    le = LabelEncoder()
    df[label_col] = le.fit_transform(df[label_col])

df = df.rename(columns={label_col: "status"})

print("\nFinal label distribution:")
print(df["status"].value_counts())


df.to_csv("cleaned_web-page-phishing.csv", index=False)
print("\nCleaned dataset saved.")



print("\n=== TRAINING MODEL ===")

X = df.drop("status", axis=1)
y = df["status"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier()
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))

joblib.dump(model, "phishing_model.pkl")
print("\nModel saved as: phishing_model.pkl")
