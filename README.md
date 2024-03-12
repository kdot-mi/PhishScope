<div align="center">
<img src="images\Logo Design-13.png">
</div>

## About
***PhishScope*** is a web application phishing email analysis tool that allows you to scan emails, URLs, and typosquatting domains for phishing links and malicious content.  It is written in <a href="https://www.python.org/downloads/">*Python 3*</a> and based on <a href="https://flask.palletsprojects.com/en/3.0.x/">*Flask*</a>. It uses the *VirusTotal* API and the **BERT** model to detect phishing emails. 

<div align="center">
<img src="images\buildingBlocks.png"><br>

*PhishScope UML Diagram*
</div>

## Getting Started
### VirusTotal API
*PhishScope* uses the *VirusTotal* API for uploading and scanning files. This allows *PhishScope* to check if a file is malicious or benign based on *VirusTotal*'s database. Additionally, it allows *PhishScope* to submit and scan URLs to determine if they lead to harmful content.

The API retrieves finished scan reports for files and URLs.

To use the API, create a **config.py** file with the API key.

**config.py**<br>
<code>VIRUSTOTAL_API_KEY = 'API KEY'</code>

Replace 'API KEY' with the <a href="https://docs.virustotal.com/reference/overview">*VirusTotal* API Key</a>.

Place the **config.py** file inside the  *Phishing-Detection-App\Flask App* directory. This is the file tree:

```
Flask App/
├─ __pycache__/
├─ instance/
├─ static/
├─ templates/
├─ venv/
├─ app.py
├─ **config.py**
├─ my_model.py
```

### Running Application Locally
*PhishScope* can run on any operating system that can install Python (Windows, Mac OS, and most Linux distributions). We recommend setting up a virtual environment and activating it (<a href="https://docs.python.org/3/tutorial/venv.html">Python 3 Virtual Environment Tutorial</a>).

Flask supports Python 3.8 and newer.

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
<code>$ python3 app.py</code>

The default Flask WSGI server (<a href="https://werkzeug.palletsprojects.com/en/3.0.x/">Werkzeug</a>) will be used. If you wish to use another WSGI server (e.g. <a href="https://gunicorn.org/">Gunicorn</a>) or use a reverse proxy (e.g. <a href="https://nginx.org/en/">NGINX</a>), read the <a href="https://flask-socketio.readthedocs.io/en/latest/deployment.html">Flask-SocketIO documentation</a>.

### Usage
<div align="center"><img src="images\webUI.png">
<i>Prototype UI</i>
</div><br>

The interface has an input area to enter a file and an upload button to submit to the *VirusTotal* API. 

**Proto Demo:**<br>
<div align="center">
<img src="images\EmailScanner.gif" align="center">
<i>Email  Scanner</i>
</div><br>

The user will input a file and click upload. That file will get sent to the *VirusTotal* API and return results labeling the file malicious or benign. It will also give a malicious score from 0% to 100%.

<br>
<div align="center">
<img src="images\AttachmentScanner.gif">
<i>Attachment Scanner</i>
</div><br>

The user will input a file and click upload. That file will get sent to the *VirusTotal* API and return 'Scan Results'. 

## Resources
### Data Set
A collection of datasets for classification and phishing detection tasks, compiled from various sources, including 18,000 Enron Corporation emails, 5,971 text messages, over 800,000 URLs, and 80,000 website instances.

https://huggingface.co/datasets/ealvaradob/phishing-dataset  

### Hugging Face Model
<div align="center">
    <img src="images\BERT.png"><br>
    <i>A schematic depiction of the BERT model and its training process</i>
</div>

<br>
<a href="https://huggingface.co/docs/transformers/model_doc/bert">Bidirectional Encoder Representations from Transformers</a> (<b>BERT</b>) model. A deep learning model which is trained on text data. Unlike traditional models that process text in one direction (either left-to-right or right-to-left), BERT considers both directions which helps it learn to understand the context of words.<br>
<br>

https://huggingface.co/rpg1/tinyBERT_phishing_model

### Practical Deep Learning
A free course that helps coders apply deep learning to practical problems. Covers building and training models for various applications using tools like PyTorch, fast.ai, and Hugging Face.

https://course.fast.ai/


## Credits
This project started in 2024 and was presented as a Senior Project for graduation at the <a href="https://www.usf.edu/">University of South Florida</a>. The team was composed by <a href="https://github.com/kdot-mi">Thurmond Guy</a>, <a href="https://github.com/YameronB">Cameron Brauner</a>, <a href="https://github.com/rpg94">Ryan Gillespie</a>, and <a href="https://github.com/RealDylanLove">Dylan Love</a>.

<div align="center">
<img src="images\University-of-South-Florida-Logo.png" width="300px">
</div>
