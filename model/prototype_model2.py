# Use a pipeline as a high-level helper
from transformers import pipeline

pipe = pipeline("text-classification", model="foghlaimeoir/phishing-DistilBERT")

res = pipe("Hey buddy how's it going?")

print(res)
