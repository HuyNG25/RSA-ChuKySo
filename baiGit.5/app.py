from flask import Flask, render_template, request, redirect, session, send_file
import os
import hashlib
import rsa
import pickle
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

users = {}
files = {}
sent_history = {}
received_history = {}

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        if password == confirm and username not in users:
            (pubkey, privkey) = rsa.newkeys(512)
            users[username] = {
                'name': name,
                'email': email,
                'password': password,
                'public': pubkey,
                'private': privkey
            }
            return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and user['password'] == password:
            session['user'] = username
            return redirect('/dashboard')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    username = session['user']
    user = users[username]

    if request.method == 'POST':
        if 'file' in request.files:
            file = request.files['file']
            filename = secure_filename(file.filename)
            path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(path)

            with open(path, 'rb') as f:
                content = f.read()
            hash_val = hashlib.sha256(content).hexdigest()
            signature = rsa.sign(hash_val.encode(), user['private'], 'SHA-256')
            files.setdefault(username, []).append((filename, hash_val, signature))

        elif 'send_file_id' in request.form:
            file_index = int(request.form['send_file_id'])
            receiver = request.form['receiver_id']
            file_data = files[username][file_index]
            sender_name = users[username]['name']
            received_history.setdefault(receiver, []).append(file_data + (sender_name,))
            sent_history.setdefault(username, []).append(file_data)

    user_files = files.get(username, [])
    sent_files = sent_history.get(username, [])
    received_files = received_history.get(username, [])
    other_users = [(u, users[u]['name']) for u in users if u != username]

    return render_template('dashboard.html', files=user_files, sent=sent_files,
                           received=received_files, users=other_users)

@app.route('/download/<filename>')
def download(filename):
    path = os.path.join(UPLOAD_FOLDER, filename)
    if os.path.exists(path):
        return send_file(path, as_attachment=True)
    return 'File này được giữ bảo mật hoặc không tồn tại.'

if __name__ == '__main__':
    app.run(debug=True)