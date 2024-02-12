# Use a pipeline as a high-level helper
from transformers import pipeline

def check_phishing(text):
    pipe = pipeline("text-classification", model="foghlaimeoir/phishing-DistilBERT")
    res = pipe(text)
    return res
