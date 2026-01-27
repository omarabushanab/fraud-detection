import lightgbm as lgb
import matplotlib.pyplot as plt
from preprocessing.uri_data_preprocessing import uri_data_preprocessing
from lightgbm import LGBMClassifier
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
    # lgb.plot_tree(
    #     model,
    #     tree_index=0,          # which tree
    #     figsize=(20, 10),
    #     show_info=["split_gain", "internal_value", "leaf_count"]
    # )

    # plt.show()

    # Create models directory
    # Path("artifacts").mkdir(exist_ok=True)

    # Save model
    joblib.dump(model, "models/uri_lgbm_model_domain_new.joblib")

    print("Model saved to models/uri_lgbm_model_domain_new.joblib")