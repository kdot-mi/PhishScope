<div align="center">
![logo](images\Logo Design-13.png)
</div>

## About
***PhishScope*** is a phishing email analysis tool that allows you to scan emails, URLs, and typosquatting domains for phishing links and malicious content.  It is writtin in *Python 3* and based on *Flask*. It uses the <a href="https://docs.virustotal.com/reference/overview">*VirusTotal*</a> API and the **BERT** model to detect phishing emails. 

## Getting Started
### Running Application Locally
PhishScope can run on any operating system that can install Python (Windows, Mac OS, and most Linux distributions). We recommend setting up a virtual environment and activating it (<a href="https://docs.python.org/3/tutorial/venv.html">Python 3 Virtual Environment Tutorial</a>).

**Install project dependencies:**
<br>
Install transformers [Need for **BERT** model] (*Required:* <a href="https://www.tenforums.com/tutorials/51704-enable-disable-win32-long-paths-windows-10-a.html">Win32 Long Paths Enabled</a>)
<br>
<code>$ pip install transformers</code>


Install database libraries
<br>
<code>$ pip install Flask-SQLAlchemy</code>
<br>
<code>$ pip install Flask-Migrate</code>

**You can now run the development server:**
<br>
Make sure you are in the *Phishing-Detection-App\Flask App* directory
<br>
<code>$ python app.py</code>

## Resources
### Data Set
Mail Dataset.

https://huggingface.co/datasets/ealvaradob/phishing-dataset  

### Hugging Face Model
<a href="https://huggingface.co/docs/transformers/model_doc/bert">Bidirectional Encoder Representations from Transformers</a> (**BERT**) model. A deep learning model which is trained on text data, and learns to understand the context of words.

https://huggingface.co/rpg1/tinyBERT_phishing_model


### Practical Deep Learning
Free course that helps coders apply deep learning to practical problems. Covers building and training models for various applications using tools like PyTorch, fastai, and Hugging Face.

https://course.fast.ai/





