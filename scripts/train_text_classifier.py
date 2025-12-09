from transformers import XLMRobertaForSequenceClassification
from transformers import XLMRobertaTokenizer, Trainer
from transformers import TrainingArguments, DataCollatorWithPadding
from datasets import Dataset, load_from_disk, load_dataset
import torch
from sklearn.metrics import accuracy_score, f1_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split


# Load dataset
dataset = load_dataset("ealvaradob/phishing-dataset", "combined_full", trust_remote_code=True)


df = dataset['train'].to_pandas()
train, test = train_test_split(df, test_size=0.2, random_state=42)
train, test = Dataset.from_pandas(train, preserve_index=False), Dataset.from_pandas(test, preserve_index=False)


# Initialize model and tokenizer
model_name = "xlm-roberta-base"
tokenizer = XLMRobertaTokenizer.from_pretrained(model_name)
model = XLMRobertaForSequenceClassification.from_pretrained(
    model_name, 
    num_labels=2,
    id2label={0: "safe", 1: "phishing"},
    label2id={"safe": 0, "phishing": 1}
)

# Tokenization function
def tokenize_function(examples):
    return tokenizer(
        examples["text"],
        truncation=True,
        max_length=512
    )

# Tokenize dataset
tokenized_datasets = dataset.map(tokenize_function, batched=True)

# Training arguments
training_args = TrainingArguments(
    output_dir="./xlm-r-phishing-detector",
    evaluation_strategy="epoch",
    learning_rate=2e-5,
    per_device_train_batch_size=16,
    per_device_eval_batch_size=16,
    num_train_epochs=5,
    weight_decay=0.01,
    save_strategy="epoch",
    load_best_model_at_end=True,
    metric_for_best_model="f1",
)

# Custom metrics

def compute_metrics(pred):
    labels = pred.label_ids
    preds = pred.predictions.argmax(-1)
    precision, recall, f1, _ = precision_recall_fscore_support(labels, preds, average='binary')
    acc = accuracy_score(labels, preds)
    return {
        'accuracy': acc,
        'f1': f1,
        'precision': precision,
        'recall': recall
    }

data_collator = DataCollatorWithPadding(tokenizer=tokenizer)

# Trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=tokenized_datasets["train"],
    eval_dataset=tokenized_datasets["val"],
    tokenizer=tokenizer,
    data_collator = data_collator,
    compute_metrics=compute_metrics,
)

# Train
trainer.train()

# Evaluate
results = trainer.evaluate(tokenized_datasets["test"])
print(results)