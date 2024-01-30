# Use a pipeline as a high-level helper
from transformers import pipeline
import warnings
import re

# filter out depecrated warning
warnings.filterwarnings("ignore", message="TypedStorage is deprecated", category=UserWarning)

pipe = pipeline("text-classification", model="ealvaradob/bert-finetuned-phishing")

res = pipe("You have access to FREE Video Streaming in your plan. REGISTER with your email,\
            password and then select the monthly subscription option. https://bit.ly/3vNrU5r")

print(res)

