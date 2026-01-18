from sklearn.metrics import roc_auc_score, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from core.preprocessing.uri_data_preprocessing import uri_data_preprocessing
import joblib
import numpy as np

MODEL_PATH = "core/models/uri_lgbm_model_domain.joblib"
model = joblib.load(MODEL_PATH)

X_train, X_val, y_train, y_val = uri_data_preprocessing()

print("Evaluating model...")

y_probs = model.predict_proba(X_val)[:, 1]

# y_probs = model.predict_proba(X_val)[:, 1]
# Choose a threshold (default 0.5)
threshold = 0.5
y_pred = (y_probs >= threshold).astype(int)

print("Confusion Matrix:")
print(confusion_matrix(y_val, y_pred))

print("Accuracy:", accuracy_score(y_val, y_pred))
print("Precision:", precision_score(y_val, y_pred))
print("Recall:", recall_score(y_val, y_pred))
print("F1 Score:", f1_score(y_val, y_pred))
print("ROC AUC:", roc_auc_score(y_val, y_probs))


def find_best_threshold(y_true, y_probs):
    thresholds = np.linspace(0.01, 0.99, 99)

    results = []

    for t in thresholds:
        y_pred = (y_probs >= t).astype(int)

        precision = precision_score(y_true, y_pred, zero_division=0)
        recall = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)

        results.append((t, precision, recall, f1))

    return results

results = find_best_threshold(y_val, y_probs)

best = max(results, key=lambda x: x[3])  # maximize F1
best_threshold, best_precision, best_recall, best_f1 = best

print(f"Best threshold: {best_threshold:.2f}")
print(f"Precision: {best_precision:.3f}")
print(f"Recall: {best_recall:.3f}")
print(f"F1-score: {best_f1:.3f}")



# X_eval, y_eval = build_disjoint_eval_csv()

# print("Evaluating model eval 2...")

# y_eval_probs = model.predict_proba(X_eval)[:, 1]

# # y_probs = model.predict_proba(X_val)[:, 1]
# # Choose a threshold (default 0.5)
# threshold = 0.5
# y_eval_pred = (y_eval_probs >= threshold).astype(int)

# print("Confusion Matrix eval 2:")
# print(confusion_matrix(y_eval, y_eval_pred))

# print("Accuracy eval 2:", accuracy_score(y_eval, y_eval_pred))
# print("Precision eval 2:", precision_score(y_eval, y_eval_pred))
# print("Recall eval 2:", recall_score(y_eval, y_eval_pred))
# print("F1 Score eval 2:", f1_score(y_eval, y_eval_pred))
# print("ROC AUC eval 2:", roc_auc_score(y_eval, y_eval_probs))
