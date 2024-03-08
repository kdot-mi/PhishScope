# Use a pipeline as a high-level helper
from transformers import pipeline

pipe = pipeline("text-classification", model="rpg1/tinyBERT_phishing_model")

res = pipe("Hey buddy how's it going?")

print(res)
