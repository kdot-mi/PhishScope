from flask import Flask, request, redirect, url_for, render_template, flash
import requests
import os
import time
from time import sleep
# from model for distilBERT, from model2 for BERT
from model2 import check_phishing
from config import VIRUSTOTAL_API_KEY


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flash messages and sessions

# Define the allowed extensions for upload
ALLOWED_EXTENSIONS = {'eml', 'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    # Render the upload form template
    return render_template('upload.html', time=time) 

@app.route('/upload', methods=['POST'])
def upload_file():
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            content = file.read().decode('utf-8')  # Assuming the file is text-based
            phishing_result = check_phishing(content)
            # Handle phishing_result as needed, e.g., flash a message to the user
            flash('File successfully uploaded. ')
            flash(str(phishing_result))
            return redirect(url_for('index'))
    return redirect(url_for('index'))

@app.route('/attachment-upload', methods=['POST'])
def attachment_upload():
    # Check if a file is part of the uploaded request
    if 'attachment' not in request.files:
        flash('No file part')
        return redirect(url_for('index'))

    # Retrieve the file from the form
    file = request.files['attachment']
    
    # Check if the filename is not empty and allowed
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Prepare the request to VirusTotal
        files = {'file': (file.filename, file.stream, 'application/octet-stream')}
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}

        # Send the file to the VirusTotal API for scanning
        response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)
        
        # Check if the request was successful
        if response.status_code == 200:
            json_response = response.json()
            resource_id = json_response['data']['id']
        
        # Wait for 15 seconds before attempting to retrieve the report
            sleep(15)

        # Make a GET request to retrieve the file report
            report_url = f"https://www.virustotal.com/api/v3/analyses/{resource_id}"
            report_headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
            report_response = requests.get(report_url, headers=report_headers)

        if report_response.status_code == 200:
            report = report_response.json()
            stats = report['data']['attributes']['stats']
    
    # Instead of redirecting, render the 'upload.html' template with the results
            return render_template('upload.html', stats=stats, show_results=True, current_time=time.time())
        else:
            flash('Failed to retrieve the report.')
    else:
        flash('Failed to scan the file. Please try again.')

    return redirect(url_for('index'))

@app.route('/url', methods=['POST'])
def upload_url():
    if request.method == 'POST':
        # Check if the post request has the URL part
        if 'url' not in request.form:
            flash('No URL part')
            return redirect(request.url)
        url = request.form['url']
        # If user does not enter URL
        if url == '':
            flash('No URL entered')
            return redirect(request.url)
        # Here, you can add your processing logic
        flash('URL successfully uploaded')
        return redirect(url_for('index'))
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=9001)
