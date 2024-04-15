from flask import Flask, request, redirect, url_for, render_template, flash
import requests
import os
import time
from time import sleep
from my_model import check_phishing
from config import VIRUSTOTAL_API_KEY, OPENAI_API_KEY
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from zoneinfo import ZoneInfo
import re
import plotly
import plotly.graph_objs as go
from collections import defaultdict
from openai import OpenAI
from datetime import datetime
import re

client = OpenAI(api_key=OPENAI_API_KEY)
import magic
from email import message_from_bytes, policy
from email.parser import BytesParser
from email.utils import parseaddr
import pdfplumber
import docx
import chardet
import time


app = Flask(__name__)

# Email 
from flask_mail import Mail, Message

app.config['MAIL_SERVER']='smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'phishscope@outlook.com'
app.config['MAIL_PASSWORD'] = 'seniorproject2024'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False

mail = Mail(app)

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
ALLOWED_EXTENSIONS = {'eml', 'txt', 'pdf', 'docx'}

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

        # Get the file type
        file_type = magic.from_buffer(file.read(), mime=True)

        # Reset the file stream
        file.seek(0)

        if file_type == 'text/plain':
            # Handle plain text files
            content = file.read().decode('utf-8')
            email_addresses = extract_email_address(content)
            mail_body = content
        elif file_type == 'message/rfc822':
            # Handle email files (e.g., .eml)
            email_message = message_from_bytes(file.read(), policy=policy.default)
            email_addresses = extract_email_address(email_message['From'])
            mail_body = get_body(email_message)
        elif file_type == 'application/pdf':
            # Handle PDF files
            with pdfplumber.open(file) as pdf:
                mail_body = ''
                for page in pdf.pages:
                    mail_body += page.extract_text()
            email_addresses = extract_email_address(mail_body)
        elif file_type == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
            # Handle DOCX files
            doc = docx.Document(file)
            mail_body = ''
            for para in doc.paragraphs:
                mail_body += para.text + '\n'
            email_addresses = extract_email_address(mail_body)
        else:
            # Handle other file types (e.g., .jpg, .png, etc.)
            flash(f'File type {file_type} is not supported')
            return redirect(request.url)

        # Call the check_phishing function
        phishing_results = check_phishing(mail_body)

        # Initialize variables
        phishing_detected = False

        if phishing_results:
            label = phishing_results[0]['label']
            score = phishing_results[0]['score']

            if label == 'phishing':
                phishing_detected = True

                if email_addresses:  # Change here to check if list is not empty
                    email_address = email_addresses[0]  # Use only the first found email
                    blacklist_email(email_address)  # Call with a single email address
                    flash('Phishing detected. Sender added to blacklist.')
                else:
                    flash('Phishing detected, but no email address found.')

                flash(f"Phishing score: {score}")
            else:
                # Flash message for benign or other non-phishing labels
                flash(f"{label.capitalize()} score: {score}")
                flash('Content deemed safe.')

        else:
            flash('No results from phishing check.')

        # Log the phishing check result
        status = 'unsafe' if phishing_detected else 'safe'
        # Adjust to handle potential list of email addresses safely
        email_address_to_log = email_addresses[0] if email_addresses else 'unknown'
        new_analytics = EmailAnalytics(email=email_address_to_log, status=status, score=phishing_results[0]['score'] if phishing_detected else 0)
        db.session.add(new_analytics)
        db.session.commit()

        return redirect(url_for('index'))

    return redirect(url_for('index'))

def get_body(email_message):
    if email_message.is_multipart():
        for payload in email_message.get_payload():
            body = get_body(payload)
            if body:
                return body
    else:
        payload = email_message.get_payload(decode=True)
        if payload:
            # Try to detect the encoding
            result = chardet.detect(payload)
            encoding = result['encoding'] if result['encoding'] else 'utf-8'

            try:
                # Try decoding the payload using the detected encoding
                body = payload.decode(encoding, errors='replace')
                return body
            except (UnicodeDecodeError, LookupError):
                # If the decoding fails, try other encodings
                for encoding in ['windows-1252', 'latin-1']:
                    try:
                        body = payload.decode(encoding, errors='replace')
                        return body
                    except UnicodeDecodeError:
                        pass

    return None

def extract_email_address(content):
    potential_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', content)
    validated_emails = []

    for email in potential_emails:
        parsed_email = parseaddr(email)[1]
        if parsed_email:
            validated_emails.append(parsed_email)

    return validated_emails


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

            # Poll for the analysis results
            report = poll_for_analysis_results(resource_id)
            if report:
                stats = report['data']['attributes']['stats']
                return render_template('upload.html', stats=stats, show_results=True, current_time=time.time())
            else:
                flash('Failed to retrieve the report.')
        else:
            flash('Failed to scan the file. Please try again.')

    return redirect(url_for('index'))

def poll_for_analysis_results(resource_id, max_attempts=30, delay=15):
    attempts = 0
    report_headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
    report_url = f"https://www.virustotal.com/api/v3/analyses/{resource_id}"

    while attempts < max_attempts:
        report_response = requests.get(report_url, headers=report_headers)
        if report_response.status_code == 200:
            report = report_response.json()
            if report['data']['attributes']['status'] == 'completed':
                return report
        attempts += 1
        time.sleep(delay)

    return None

@app.route('/url', methods=['POST'])
def scan_url():
    human_readable_date = None  # Initialize to handle the case where no date is found
    url_to_scan = request.form['url']
    submission_headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY,
        "content-type": "application/x-www-form-urlencoded"
    }
    payload = {"url": url_to_scan}
    response = requests.post('https://www.virustotal.com/api/v3/urls', data=payload, headers=submission_headers)
    print(response)
    
    if response.status_code == 200:
        url_id = response.json()['data']['id'].split('-')[1]
        report_url = f'https://www.virustotal.com/api/v3/urls/{url_id}'
        report_headers = {"accept": "application/json", "x-apikey": VIRUSTOTAL_API_KEY}
        report_response = requests.get(report_url, headers=report_headers)
        
        if report_response.status_code == 200:
            results = report_response.json()['data']['attributes']['last_analysis_stats']

            domain = url_to_scan.split("//")[-1].split("/")[0]  # Extract just the domain from the URL
            whois_url = f"https://www.virustotal.com/api/v3/domains/{domain}/historical_whois?limit=10"
            whois_response = requests.get(whois_url, headers=submission_headers)

            if whois_response.status_code == 200:
                whois_data = whois_response.json()
                creation_date = None
                for data_entry in whois_data.get('data', []):
                    whois_map = data_entry.get('attributes', {}).get('whois_map', {})
                    creation_date = whois_map.get('Creation Date')
                    if creation_date:
                        match = re.search(r'\d{4}-\d{2}-\d{2}', creation_date)
                        if match:
                            date_part = match.group(0)
                            parsed_date = datetime.strptime(date_part, "%Y-%m-%d")
                            human_readable_date = parsed_date.strftime("%m/%d/%Y")
                            break  # Found a valid date, break out of the loop

            results_file = os.path.join(app.root_path, 'url_scan_results.txt')
            print("Executing file SAVE")
            with open(results_file, 'a') as f:
                f.write(f'URL: {url_to_scan}\n')
                f.write(f'Results: {str(results)}\n\n')
                f.write(f'WHOIS Data: {str(whois_data)}\n\n')

            return render_template('upload.html', show_url_results=True, stats=results, creation_date=human_readable_date or "Not Available", current_time=time.time())

        else:
            print(f"Error: {report_response.status_code}")
            print(report_response.text)  # Print the error response
            return redirect(url_for('index'))  # Redirect or handle the error as appropriate
    else:
        print(f"Error scanning URL: {response.status_code}")
        print(response.text)
        return redirect(url_for('error_page', error=response.text))  # Redirect to an error handling page

@app.route('/analytics')
def analytics():
    # Query the EmailAnalytics table to get the data
    email_analytics = EmailAnalytics.query.all()

    # Count the number of safe and unsafe emails
    safe_count = sum(1 for email in email_analytics if email.status == 'safe')
    unsafe_count = sum(1 for email in email_analytics if email.status == 'unsafe')

    # Create the pie chart data
    labels = ['Safe', 'Unsafe']
    values = [safe_count, unsafe_count]

    # Create the pie chart
    pie_chart = go.Figure(data=[go.Pie(labels=labels, values=values)])
    pie_chart.update_layout(title='Safe vs Unsafe Emails')
    pie_div = plotly.offline.plot(pie_chart, output_type='div', include_plotlyjs=False)

    # Get the data grouped by date and status
    email_data = defaultdict(lambda: {'safe': 0, 'unsafe': 0})
    for email in email_analytics:
        date = email.date_analyzed.date()
        status = email.status
        email_data[date][status] += 1

    # Create the line chart data
    dates = sorted(email_data.keys())
    safe_counts = [email_data[date]['safe'] for date in dates]
    unsafe_counts = [email_data[date]['unsafe'] for date in dates]

    # Create the line chart
    line_chart = go.Figure()
    line_chart.add_trace(go.Scatter(x=dates, y=safe_counts, mode='lines', name='Safe'))
    line_chart.add_trace(go.Scatter(x=dates, y=unsafe_counts, mode='lines', name='Unsafe'))
    line_chart.update_layout(title='Email Analysis Trend', xaxis_title='Date', yaxis_title='Count')

    # Convert the plotly figure to HTML
    line_div = plotly.offline.plot(line_chart, output_type='div', include_plotlyjs=False)

    # Group the email data by score range and status
    score_ranges = [(0, 0.2), (0.2, 0.4), (0.4, 0.6), (0.6, 0.8), (0.8, 1)]
    email_data = {(start, end): {'safe': 0, 'unsafe': 0} for start, end in score_ranges}
    for email in email_analytics:
        score = email.score
        status = email.status
        for start, end in score_ranges:
            if start <= score < end:
                email_data[(start, end)][status] += 1

    # Create the bar chart data
    x_labels = [f"{start:.1f} - {end:.1f}" for start, end in score_ranges]
    safe_counts = [email_data[(start, end)]['safe'] for start, end in score_ranges]
    unsafe_counts = [email_data[(start, end)]['unsafe'] for start, end in score_ranges]

    # Create the bar chart
    bar_chart = go.Figure(data=[
        go.Bar(x=x_labels, y=safe_counts, name='Safe'),
        go.Bar(x=x_labels, y=unsafe_counts, name='Unsafe')
    ])
    bar_chart.update_layout(title='Email Status Distribution by Score Range', xaxis_title='Score Range', yaxis_title='Count', barmode='group')

    # Convert the plotly figure to HTML
    bar_div = plotly.offline.plot(bar_chart, output_type='div', include_plotlyjs=False)

    # Get the data for score and analysis date
    scores = [email.score for email in email_analytics]
    dates = [email.date_analyzed for email in email_analytics]

    # Create the scatter plot
    scatter_plot = go.Figure(data=go.Scatter(x=dates, y=scores, mode='markers'))
    scatter_plot.update_layout(title='Email Score vs. Analysis Date', xaxis_title='Analysis Date', yaxis_title='Score')

    # Convert the plotly figure to HTML
    scatter_div = plotly.offline.plot(scatter_plot, output_type='div', include_plotlyjs=False)

    return render_template('analytics.html', pie_div=pie_div, line_div=line_div, bar_div=bar_div, scatter_div=scatter_div)

@app.route('/chatbot', methods=['GET', 'POST'])
def chatbot():
    if request.method == 'POST':
        user_input = request.form['user_input']
        response = generate_response(user_input)
        return render_template('chatbot.html', response=response)
    return render_template('chatbot.html')


def generate_response(prompt):
    response = client.chat.completions.create(model="gpt-3.5-turbo",
    messages=[
        {"role": "user", "content": prompt}
    ])

    message = response.choices[0].message.content
    return message

@app.route('/blacklist', methods=['GET', 'POST'])
def manage_blacklist():
    if request.method == 'POST':
        # Handle adding or removing emails from the blacklist
        if 'add_email' in request.form:
            email = request.form['email']
            if not Blacklist.query.filter_by(email=email).first():
                new_blacklist_entry = Blacklist(email=email)
                db.session.add(new_blacklist_entry)
                db.session.commit()
                flash(f'Email {email} added to the blacklist.', 'success')
            else:
                flash(f'Email {email} is already in the blacklist.', 'warning')
        elif 'remove_email' in request.form:
            email = request.form['email']
            blacklist_entry = Blacklist.query.filter_by(email=email).first()
            if blacklist_entry:
                db.session.delete(blacklist_entry)
                db.session.commit()
                flash(f'Email {email} removed from the blacklist.', 'success')
            else:
                flash(f'Email {email} is not in the blacklist.', 'warning')

    # Retrieve the blacklist entries from the database
    blacklist_entries = Blacklist.query.all()

    return render_template('blacklist.html', blacklist_entries=blacklist_entries)


# Feedback
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        email = request.form['email']
        feedback = request.form['feedback']
        rating = request.form['rating']

        msg = Message('New Feedback', sender = 'phishscope@outlook.com', recipients = ['phishscope@outlook.com'])
        msg.body = f"Email: {email}\nFeedback: {feedback}\nRating: {rating}"
        mail.send(msg)

    return render_template('feedback.html')

# Training
@app.route('/training')
def training():
    # Render the training page
    return render_template('training.html')


if __name__ == '__main__':
    app.run(debug=True, port=9001)
