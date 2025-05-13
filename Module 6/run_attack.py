import sys
import csv
import nltk
from textattack.attack_recipes import TextFoolerJin2019
from textattack.attack_args import AttackArgs
from textattack.attacker import Attacker
from textattack.datasets import Dataset
import requests
from textattack.models.wrappers import ModelWrapper

# Explicitly download the missing resource.
try:
    nltk.download("averaged_perceptron_tagger_eng", quiet=True)
except Exception as e:
    print("Error downloading averaged_perceptron_tagger_eng:", e)

# --- Custom Model Wrapper ---
# Save this code in domain_analyzer_wrap.py (or include it in this file if preferred).
class DomainAnalyzerAPIBasedWrapper(ModelWrapper):
    def __init__(self, api_url="http://localhost:5000/predict"):
        self.api_url = api_url
        self.model = self  # Satisfies the goal function requirement

    def __call__(self, text_input_list):
        predictions = []
        for text in text_input_list:
            try:
                response = requests.post(
                    self.api_url,
                    json={"text": text},
                    timeout=5
                )
                response.raise_for_status()
                data = response.json()
                # For classification, we produce a dummy probability distribution.
                pred_score = data.get("prediction", 0.0)
                predictions.append([1 - pred_score, pred_score])
            except Exception as e:
                print(f"Error processing text: {text[:30]}... -> {e}")
                predictions.append([1.0, 0.0])
        return predictions

# --- Custom Dataset Loader ---
def load_dataset_from_csv(csv_path, text_column="subject"):
    """
    Reads a CSV file and extracts examples as tuples: (text, gold_label).
    Here we set the gold label to a dummy integer value (1) to satisfy
    the UntargetedClassification goal function.
    """
    examples = []
    with open(csv_path, "r", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            text = row.get(text_column, "")
            if text:
                examples.append((text, 1))
    return examples

# --- Main Attack Script ---
def main():
    # Use the real CSV file name directly.
    csv_path = "Nigerian_Fraud_processed_20250321_203134.csv"
    
    # Load the dataset using the "subject" column.
    dataset = load_dataset_from_csv(csv_path, text_column="subject")
    if not dataset:
        print("No data loaded. Check that the CSV file exists and the column name is correct.")
        sys.exit(1)
    
    # Instantiate your custom model wrapper that calls the /predict endpoint.
    model_wrapper = DomainAnalyzerAPIBasedWrapper(api_url="http://localhost:5000/predict")
    
    # Build the attack using the TextFoolerJin2019 recipe.
    attack = TextFoolerJin2019.build(model_wrapper)
    
    # Set up attack arguments (attacking 20 examples, logging output to a CSV).
    attack_args = AttackArgs(
        num_examples=20,
        log_to_csv="attack_results.csv",
        disable_stdout=False,
        random_seed=42
    )
    
    # Create an attacker instance with the built attack, dataset, and attack arguments.
    attacker = Attacker(attack, Dataset(dataset), attack_args)
    
    # Run the attack on the dataset.
    attacker.attack_dataset()

if __name__ == "__main__":
    main()

