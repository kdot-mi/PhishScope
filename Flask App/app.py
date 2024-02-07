from flask import Flask, request, redirect, url_for, render_template, flash
import time 

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
            # Here, you can add your processing logic
            flash('File successfully uploaded')
            return redirect(url_for('index'))
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
