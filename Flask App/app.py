from flask import Flask, request, redirect, url_for, render_template, flash
import requests
import os
import time
from time import sleep
from my_model import check_phishing
from config import VIRUSTOTAL_API_KEY
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from zoneinfo import ZoneInfo
import re


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Needed for flash messages and sessions

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishScope.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Blacklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)

class EmailAnalytics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)  # 'safe' or 'unsafe'
    date_analyzed = db.Column(db.DateTime, default=lambda: datetime.now(ZoneInfo("America/New_York")))
    score = db.Column(db.Float, nullable=True)  # Add this line

with app.app_context():
    db.create_all()

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
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '' or not allowed_file(file.filename):
            flash('No selected file or file type not allowed')
            return redirect(request.url)

        flash('Upload Successful')

        # Decode the file content
        content = file.read().decode('utf-8')  # Assuming the file is text-based

        # Call the check_phishing function
        phishing_results = check_phishing(content)

        # Initialize variables
        email_address = None  # Initialize email_address with a default value

        if phishing_results:
            label = phishing_results[0]['label']
            score = phishing_results[0]['score']
            
            if label == 'phishing':
                phishing_detected = True
                email_address = extract_email_address(content)
                
                if email_address:
                    blacklist_email(email_address)
                    flash('Phishing detected. Sender added to blacklist.')
                else:
                    flash('Phishing detected, but no email address found.')
                
                flash(f"Phishing score: {score}")
            else:
                phishing_detected = False
                # Flash message for benign or other non-phishing labels
                flash(f"{label.capitalize()} score: {score}")
                flash('Content deemed safe.')

        else:
            flash('No results from phishing check.')

        
        

        # Log the phishing check result
        status = 'unsafe' if phishing_detected else 'safe'
        new_analytics = EmailAnalytics(email=email_address or 'unknown', status=status, score=phishing_results[0]['score'] if phishing_detected else 0)
        db.session.add(new_analytics)
        db.session.commit()

        return redirect(url_for('index'))
    
    return redirect(url_for('index'))



def extract_email_address(content):
    # A simple regex for extracting an email address
    match = re.search(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
    return match.group(0) if match else None

def blacklist_email(email_address):
    # Check if the email address is already in the blacklist to prevent duplicates
    if not Blacklist.query.filter_by(email=email_address).first():
        new_blacklist_entry = Blacklist(email=email_address)
        db.session.add(new_blacklist_entry)
        db.session.commit()


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
