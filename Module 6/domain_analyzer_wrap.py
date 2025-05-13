import requests
from textattack.models.wrappers import ModelWrapper

class DomainAnalyzerWrapper(ModelWrapper):
    def __init__(self, endpoint="http://10.0.2.15:5000/predict"):
        self.endpoint = endpoint

    def __call__(self, text_list):
        predictions = []
        for text in text_list:
            try:
                response = requests.post(self.endpoint, json={"text": text}, timeout=5)
                response.raise_for_status()  # Raise error if request failed.
                data = response.json()
                # The endpoint returns a key "prediction" in the JSON response.
                prediction = data.get("prediction", None)
            except Exception as e:
                print(f"Error processing text: {text[:30]}... -> {e}")
                prediction = None
            predictions.append(prediction)
        return predictions

if __name__ == "__main__":
    wrapper = DomainAnalyzerWrapper()
    sample_texts = [
        "Urgent: Confirm your account now.",
        "Just a test email message."
    ]
    preds = wrapper(sample_texts)
    print("Predictions:", preds)

