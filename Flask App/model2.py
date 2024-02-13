# Use a pipeline as a high-level helper
from transformers import pipeline

def check_phishing(text):
    pipe = pipeline("text-classification", model="ealvaradob/bert-finetuned-phishing", truncation=True, max_length=512)
    res = pipe(text)
    return res