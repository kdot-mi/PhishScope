<div align="center">
<img src="images\Logo Design-13.png">
</div>

## About
***PhishScope*** is a web application phishing email analysis tool that allows you to scan emails, URLs, and typosquatting domains for phishing links and malicious content.  It is written in *Python 3* and based on *Flask*. It uses the <a href="https://docs.virustotal.com/reference/overview">*VirusTotal*</a> API and the **BERT** model to detect phishing emails. 

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
<code>$ python3 app.py</code>

The default Flask WSGI server (<a href="https://werkzeug.palletsprojects.com/en/3.0.x/">Werkzeug</a>) will be used. If you wish to use another WSGI server (e.g. <a href="https://gunicorn.org/">Gunicorn</a>) or use a reverse proxy (e.g. <a href="https://nginx.org/en/">NGINX</a>), read the <a href="https://flask-socketio.readthedocs.io/en/latest/deployment.html">Flask-SocketIO documentation</a>.

### Usage
<div align="center"><img src="images\webUI.png">
<i>Prototype UI</i>
</div><br>



## Resources
### Data Set
A collection of datasets for classification and phishing detection tasks, compiled from various sources, including 18,000 Enron Corporation emails, 5,971 text messages, over 800,000 URLs, and 80,000 website instances.

https://huggingface.co/datasets/ealvaradob/phishing-dataset  

### Hugging Face Model
<div align="center">
    <img src="images\BERT.png">
    <i>A schematic depiction of the BERT model and its training process</i>
</div>

<br>
<a href="https://huggingface.co/docs/transformers/model_doc/bert">Bidirectional Encoder Representations from Transformers</a> (<b>BERT</b>) model. A deep learning model which is trained on text data, and learns to understand the context of words.<br>
<br>

https://huggingface.co/rpg1/tinyBERT_phishing_model

### Practical Deep Learning
A free course that helps coders apply deep learning to practical problems. Covers building and training models for various applications using tools like PyTorch, fast.ai, and Hugging Face.

https://course.fast.ai/


## Credits
This project started in 2024 and was presented as a Senior Project for graduation at the <a href="https://www.usf.edu/">University of South Florida</a>. The team was composed by <a href="https://github.com/kdot-mi">Thurmond Guy</a>, <a href="https://github.com/YameronB">Cameron Brauner</a>, <a href="https://github.com/rpg94">Ryan Gillespie</a>, and Dylan Love.
