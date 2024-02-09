# Use a pipeline as a high-level helper
from transformers import pipeline

pipe = pipeline("text-classification", model="dima806/phishing-email-detection")

res = pipe("You have access to FREE Video Streaming in your plan. REGISTER with your email,\
            password and then select the monthly subscription option. https://bit.ly/3vNrU5r")

print(res)