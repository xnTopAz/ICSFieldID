import json
import logging
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.cluster import KMeans
from sklearn.metrics import (
    classification_report,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    silhouette_score,
    adjusted_rand_score
)
import matplotlib.pyplot as plt
import seaborn as sns

feature_names = []

def init_feature_names():
    global feature_names
    with open("tags.json") as f:
        feature_names = json.load(f)

def load_dataset(feature_path):
    """
    Load a JSON dataset and split features and labels
    :param feature_path: path to feature file
    :return: (X, y, categories)
    """
    with open(feature_path, 'r') as f:
        feature_data = json.load(f)

    data = []
    for frame_number, frame_data in feature_data.items():
        for field_name, field_data in frame_data.items():
            feature = field_data['feature']
            if len(feature) != len(feature_names):
                print(f'{frame_number} {field_name} feature size mismatch: expected {len(feature_names)}, got {len(feature)}, skipped')
                continue
            classification = field_data['tag']
            data.append({'feature': feature, 'classification': str(classification)})

    print(f"Loaded dataset: {feature_path}, total samples: {len(data)}")

    X = []
    y = []
    categories = []
    for item in data:
        feature = item["feature"]
        X.append(feature)

        label = str(item["classification"]).strip()
        y.append(label)

        if label not in categories:
            categories.append(label)

    X = np.array(X)
    y = np.array(y)
    categories = sorted(categories)

    print(f"Feature shape: {X.shape}, category count: {len(categories)}, categories: {categories}")
    return X, y, categories

def train_random_forest(X_train, y_train, n_estimators=100, max_depth=8):
    """
    Train a Random Forest classifier.
    """
    rf_model = RandomForestClassifier(
        n_estimators=n_estimators,
        max_depth=max_depth,
        random_state=42,
        class_weight="balanced"
    )

    logging.info(f"Start training Random Forest (trees: {n_estimators}, max depth: {max_depth})")
    rf_model.fit(X_train, y_train)
    print("Training complete")

    return rf_model

def evaluate_model(model: RandomForestClassifier, X_test, y_test, categories):
    y_pred = model.predict(X_test)

    # Macro-average: treats all classes equally
    precision_macro = precision_score(y_test, y_pred, labels=categories, average="macro")
    recall_macro = recall_score(y_test, y_pred, labels=categories, average="macro")
    f1_macro = f1_score(y_test, y_pred, labels=categories, average="macro")

    # Micro-average: weighted by sample size
    precision_micro = precision_score(y_test, y_pred, labels=categories, average="micro")
    recall_micro = recall_score(y_test, y_pred, labels=categories, average="micro")
    f1_micro = f1_score(y_test, y_pred, labels=categories, average="micro")

    # Detailed report per class
    class_report = classification_report(
        y_test, y_pred,
        labels=categories,
        target_names=[f"Class {c}" for c in categories],
        output_dict=True
    )

    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred, labels=categories)

    # Organize metrics
    metrics = {
        "macro": {
            "precision": precision_macro,
            "recall": recall_macro,
            "f1": f1_macro
        },
        "micro": {
            "precision": precision_micro,
            "recall": recall_micro,
            "f1": f1_micro
        },
        "class_detail": class_report,
        "confusion_matrix": cm,
        "categories": categories
    }

    print("\n===== Evaluation Results =====")
    print(f"Macro Average - Precision: {precision_macro:.4f}, Recall: {recall_macro:.4f}, F1: {f1_macro:.4f}")
    print(f"Micro Average - Precision: {precision_micro:.4f}, Recall: {recall_micro:.4f}, F1: {f1_micro:.4f}")
    print("\nPer-class metrics:")
    for c in categories:
        c_key = f"Class {c}"
        if c_key in class_report:
            print(
                f"{c_key} - Precision: {class_report[c_key]['precision']:.4f}, "
                f"Recall: {class_report[c_key]['recall']:.4f}, "
                f"F1: {class_report[c_key]['f1-score']:.4f}, "
                f"Support: {class_report[c_key]['support']}"
            )

    return metrics

def data_train(database_path=None, test_size=0.3, n_estimators=100):
    init_feature_names()

    X, y, categories = load_dataset(database_path)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=test_size,
        random_state=42,
        stratify=y
    )

    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    rf_model = train_random_forest(X_train, y_train, n_estimators=n_estimators, max_depth=8)
    metrics = evaluate_model(rf_model, X_test, y_test, categories)
    print("\nTraining and evaluation completed!")
    return rf_model, metrics

def data_train_and_test(train_db_path=None, test_db_path=None, n_estimators=100):
    init_feature_names()

    # Load training dataset
    X_train, y_train, train_categories = load_dataset(train_db_path)

    # Load test dataset
    X_test, y_test, test_categories = load_dataset(test_db_path)

    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    # Train Random Forest
    rf_model = train_random_forest(X_train, y_train, n_estimators=n_estimators, max_depth=8)
    # Evaluate
    metrics = evaluate_model(rf_model, X_test, y_test, test_categories)
    return rf_model, metrics

def data_train_and_test_2(train_db_paths, test_db_path, n_estimators=100):
    init_feature_names()
    sample_size = 500

    # Load and merge training datasets
    X_train_list, y_train_list = [], []
    for db_path in train_db_paths:
        X, y, _ = load_dataset(db_path)

        if len(X) > sample_size:
            # Stratified sampling
            X_sample, _, y_sample, _ = train_test_split(
                X, y,
                test_size=len(X) - sample_size,
                random_state=42,
                stratify=y
            )
        else:
            X_sample, y_sample = X, y

        X_train_list.append(X_sample)
        y_train_list.append(y_sample)

    X_train = np.concatenate(X_train_list, axis=0)
    y_train = np.concatenate(y_train_list, axis=0)

    # Load test dataset
    X_test, y_test, test_categories = load_dataset(test_db_path)

    print(f"Train samples: {len(X_train)}, Test samples: {len(X_test)}")

    # Train classifier
    rf_model = train_random_forest(X_train, y_train, n_estimators=n_estimators, max_depth=8)
    # Evaluate
    metrics = evaluate_model(rf_model, X_test, y_test, test_categories)
    return rf_model, metrics

if __name__ == '__main__':
    data_train('./data/bacnet.features.handled.json')
    # data_train('./data/bacnet.features.handled.a.json')
    # data_train('./data/bacnet.features.handled.b.json')
    # data_train('./data/bacnet.features.handled.c.json')
    # data_train('./data/mms.features.handled.json')
    # data_train('./data/mms.features.handled.a.json')
    # data_train('./data/mms.features.handled.b.json')
    # data_train('./data/mms.features.handled.c.json')
    # data_train_and_test('./data/bacnet.features.handled.json', './data/mms.features.handled.json')
    # data_train_and_test('./data/mms.features.handled.json', './data/bacnet.features.handled.json')

    # data_train_and_test_2(["./data/mms.features.handled.json", "./data/bacnet.features.handled.json"], "./data/s7.features.handled.json")
