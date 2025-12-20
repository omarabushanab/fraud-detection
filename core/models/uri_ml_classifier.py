import lightgbm as lgb
import matplotlib.pyplot as plt
from core.preprocessing.uri_data_preprocessing import build_disjoint_eval_csv, uri_data_preprocessing
from lightgbm import LGBMClassifier
from sklearn.metrics import roc_auc_score, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import joblib
from pathlib import Path


def train_model():
    X_train, X_val, y_train, y_val = uri_data_preprocessing()

    model = LGBMClassifier(
        n_estimators=400,
        learning_rate=0.05,
        num_leaves=64,
        max_depth=-1,
        class_weight={0: 1, 1: 3},  # penalize FP
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42
    )

    print("Training model...")
    model.fit(X_train, y_train)

    # Plot the first tree
    lgb.plot_tree(
        model,
        tree_index=0,          # which tree
        figsize=(20, 10),
        show_info=["split_gain", "internal_value", "leaf_count"]
    )

    plt.show()

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



    X_eval, y_eval = build_disjoint_eval_csv()

    print("Evaluating model eval 2...")

    y_eval_probs = model.predict_proba(X_eval)[:, 1]

    # y_probs = model.predict_proba(X_val)[:, 1]
    # Choose a threshold (default 0.5)
    threshold = 0.5
    y_eval_pred = (y_eval_probs >= threshold).astype(int)

    print("Confusion Matrix eval 2:")
    print(confusion_matrix(y_eval, y_eval_pred))

    print("Accuracy eval 2:", accuracy_score(y_eval, y_eval_pred))
    print("Precision eval 2:", precision_score(y_eval, y_eval_pred))
    print("Recall eval 2:", recall_score(y_eval, y_eval_pred))
    print("F1 Score eval 2:", f1_score(y_eval, y_eval_pred))
    print("ROC AUC eval 2:", roc_auc_score(y_eval, y_eval_probs))

    # Create models directory
    Path("artifacts").mkdir(exist_ok=True)

    # Save model
    joblib.dump(model, "core/models/uri_lgbm_model.joblib")

    print("Model saved to core/models/uri_lgbm_model.joblib")