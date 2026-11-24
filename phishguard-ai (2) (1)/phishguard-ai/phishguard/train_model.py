"""Train the optional text classifier. Run:  python train_model.py [--csv data.csv]

The CSV needs two columns: text, label (1 = phishing, 0 = legitimate).
Without --csv a tiny built-in sample is used. That is only enough to demo the
pipeline, so train on a real corpus before trusting the model.
"""
import argparse
import csv

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

PHISH = [
    "Urgent: your account has been suspended. Verify your password immediately at the link below to avoid permanent closure.",
    "Dear customer, we detected unauthorized activity on your PayPal account. Click here to confirm your identity within 24 hours.",
    "Your package could not be delivered. Pay a small redelivery fee now to release your parcel.",
    "Congratulations! You have won a $1000 gift card. Claim your prize now by entering your card details.",
    "Final notice: your Microsoft 365 password expires today. Click below to keep your current password.",
    "IT Helpdesk: mailbox storage full. Re-enter your login credentials to avoid deactivation.",
    "Invoice attached. Open the attachment and enable content to view payment details. Payment overdue.",
    "Your Apple ID was locked for security reasons. Confirm your billing information to unlock it.",
    "We noticed a suspicious sign-in to your bank account. Verify your card number and PIN to secure your funds.",
    "Action required: confirm your payroll details today or your salary will be delayed. Reply with your SSN and bank account number.",
    "Netflix: your payment was declined. Update your payment method immediately to avoid cancellation.",
    "I need a wire transfer urgently. Buy gift cards and send me the codes. Keep this confidential.",
    "Your crypto wallet has been limited. Enter your recovery phrase to restore access.",
    "Tax refund pending. Submit your bank details at the link to receive your refund.",
]
LEGIT = [
    "Hi team, the sprint review is moved to Thursday at 2pm. The agenda is in the shared doc.",
    "Thanks for your order. Your receipt is attached and your package ships tomorrow.",
    "Reminder: dentist appointment on Monday at 9:30. Reply C to confirm or call us to reschedule.",
    "Can you review my pull request when you get a chance? Tests pass locally.",
    "Happy birthday! Let's grab dinner this weekend, I'll book a table.",
    "Your monthly statement is ready. Open the app you already use to view it.",
    "Lunch at noon? The new ramen place opened near the office.",
    "Meeting notes from today are posted in the project folder. Let me know if I missed anything.",
    "Your flight check-in opens tomorrow. Have a great trip!",
    "Thanks for attending the webinar. The slides and recording are on our website.",
    "Don't forget to call grandma tonight.",
    "Your library book is due next Friday. You can renew it at the front desk.",
    "The quarterly report draft is ready for comments. Please add feedback by end of week.",
    "We've updated our privacy policy. No action is needed from you.",
]


def load(path):
    if not path:
        return PHISH + LEGIT, [1] * len(PHISH) + [0] * len(LEGIT)
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return [r["text"] for r in rows], [int(r["label"]) for r in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", help="training data with text,label columns")
    ap.add_argument("--out", default="model.joblib")
    args = ap.parse_args()
    X, y = load(args.csv)
    model = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, strip_accents="unicode"),
        LogisticRegression(max_iter=1000, class_weight="balanced"),
    )
    if len(X) >= 100:
        Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)
        model.fit(Xtr, ytr)
        print(classification_report(yte, model.predict(Xte), target_names=["legit", "phishing"]))
    else:
        print(f"Only {len(X)} examples: skipping evaluation. Use a larger dataset for real use.")
    model.fit(X, y)
    joblib.dump(model, args.out)
    print("Saved", args.out)


if __name__ == "__main__":
    main()
