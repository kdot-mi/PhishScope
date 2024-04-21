<div align="center">
<img src="images\Logo Design-13.png">
</div>

## About
***PhishScope*** is a web application phishing email analysis tool that allows you to scan emails, URLs, and typosquatting domains for phishing links and malicious content.  It is written in <a href="https://www.python.org/downloads/">*Python 3*</a> and based on <a href="https://flask.palletsprojects.com/en/3.0.x/">*Flask*</a>. It uses the *VirusTotal* API and the **BERT** model to detect phishing emails. 

<div align="center">
<img src="images\buildingBlocks.png"><br>

*PhishScope UML Diagram*
</div>

Visit Website: <a href="https://rpg1.pythonanywhere.com/">***PhishScope***</a>

## Getting Started
### Email
To use the *Feedback* functionality, go into the **app.py** file and search (<code>ctrl + f</code>) for:
```
app.config['MAIL_USERNAME'] = 'YOUREMAIL@OUTLOOK.COM'
app.config['MAIL_PASSWORD'] = 'YOUREMAILPASSWORD'
```
Replace, 'YOUREMAIL<area>@OUTLOOK.COM' and 'YOUREMAILPASSWORD' with your preferred email and passowrd.
The feedback page will send user's responses to that email.

### VirusTotal API
*PhishScope* uses the *VirusTotal* API for uploading and scanning files. This allows *PhishScope* to check if a file is malicious or benign based on *VirusTotal*'s database. Additionally, it allows *PhishScope* to submit and scan URLs to determine if they lead to harmful content.

The API retrieves finished scan reports for files and URLs.

### OpenAI
*PhishScope* uses the *OpenAI*'s API key for chatbot functionality. The chatbot can assist users: by (1) Guiding users through the process of scanning email, URLs, and files; (2) Explain Concepts of phishing, how phishing attacks work, and common tactics; and (3) Describing the characteristics of phishing emails and websites, helping users to identify threats.

To use the APIs, create a **config.py** file with the API keys.

**config.py**<br>
<code>VIRUSTOTAL_API_KEY = 'API KEY'</code>
<br>
<code>OPENAI_API_KEY = 'API KEY'</code>

Replace 'API KEY' with the <a href="https://docs.virustotal.com/reference/overview">*VirusTotal*</a> & <a href="https://help.openai.com/en/articles/4936850-where-do-i-find-my-openai-api-key">*OPENAI*</a> API Keys.

Place the **config.py** file inside the *Phishing-Detection-App\Flask App* directory. This is the file tree:

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

The **requirements.txt** file inside the *Phishing-Detection-App\Flask App* directory should list all Python libraries and dependencies that *PhishScope* uses. Use pip to install:
```
pip install -r requirements.txt
```

If you need to install the project dependencies manually, check below for installation.

**Project Dependencies:**
<br>
Install transformers [Need for **BERT** model] (*Required:* <a href="https://www.tenforums.com/tutorials/51704-enable-disable-win32-long-paths-windows-10-a.html">Win32 Long Paths Enabled</a>)
<br>
<code>$ pip install transformers</code>
<br>

Other Dependencies
<br>
<code>$ pip install plotly</code>
<br>
<code>$ pip install openai</code>
<br>
<code>$ pip install python-magic</code>
<br>
<code>$ pip install pdfplumber</code>
<br>
<code>$ pip install python-docx</code>
<br>
<code>$ pip install chardet</code>
<br>
<code>$ pip install tzdata</code>

Install Database Libraries
<br>
<code>$ pip install Flask-SQLAlchemy</code>
<br>
<code>$ pip install Flask-Migrate</code>

**CHECK** the <a href="Flask App\requirements.txt">**requirements.txt**</a> file for any other dependencies missing in the manual install. 
<br>

**You can now run the development server:**
<br>
Make sure you are in the *Phishing-Detection-App\Flask App* directory
<br>
```
python3 app.py
```

The default Flask WSGI server (<a href="https://werkzeug.palletsprojects.com/en/3.0.x/">Werkzeug</a>) will be used. If you wish to use another WSGI server (e.g. <a href="https://gunicorn.org/">Gunicorn</a>) or use a reverse proxy (e.g. <a href="https://nginx.org/en/">NGINX</a>), read the <a href="https://flask-socketio.readthedocs.io/en/latest/deployment.html">Flask-SocketIO documentation</a>.

### Usage
<div align="center"><img src="images\webUI.png">
<i>User Interface</i>
<br>
</div>
<br>
There is a top navbar that allows access to the <b>Upload</b> (current/homepage), <b>Analytics</b>, <b>Chatbot</b>, <b>Blacklist</b>, and <b>Feedback</b> pages. There is another navbar or mininav bar that the user can select between <b>Email Upload</b>, <b>Attachment Scanner</b>, and <b>URL Check</b> parts of the tool. The initial UI shows an input area to enter a file and an upload button to submit to the <i>VirusTotal</i> API. 

<br>
<div align="center">
<video controls>
    <source src="images/final_demo4 - 1713429072211.mp4" type="video/mp4">
</video><i>Demo</i>
<br>
<br>
</div>

**Email Upload**
<br>
The user will input a file and click 'Upload'. That file will get sent to the *VirusTotal* API and return results labeling the file malicious or benign. It will also give a malicious score from 0% to 100%.

**Attachment Scanner**
<br>
The user will input a file and click 'Upload'. That file will get sent to the *VirusTotal* API and return 'Scan Results'. 

**URL Check**
<br>
THe user will input a URL and click 'Check URL'. It will return Results similar to the 'Scan Results' from the Attachment Scanner, additionally it will show WHOIS information (domain registered date).

**Simulated Training**
<br>
A mini quiz that trains and explains phishing techniques to the user.

**Analytics**
<br>
Analytics dashboard that shows visualized statistics about the emails that have been analyzed. For example, split between safe and unsafe emails. The user can also download a PDF of the Analytics page.

**Chatbot**
<br>
Integration of *OpenAI API*, that allows users to ask for more information about phishing emails.

**Blacklist**
<br>
Allows users to build a list of known phishing email addresses. If an email was detected to be suspicious in one of the scanners, it will automatically be blacklisted. Users can also manually add/remove emails.

**Feedback**
<br>
User Feedback system that allows users to rate the accuracy and usefulness of phishing email detection, and provide  provide feedback or suggestions.


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
