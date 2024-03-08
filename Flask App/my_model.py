# Use a pipeline as a high-level helper
from transformers import pipeline

def check_phishing(text):
    pipe = pipeline("text-classification", model="rpg1/tinyBERT_phishing_model", truncation=True, max_length=512)
    res = pipe(text)
    return res
