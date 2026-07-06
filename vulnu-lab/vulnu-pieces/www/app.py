from flask import Flask, request
import sqlite3
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

conn = sqlite3.connect(':memory:', check_same_thread=False)
conn.executescript('''
CREATE TABLE users (username TEXT, password TEXT);
INSERT INTO users VALUES ('admin', 'admin123'), ('student1', 'student123');
''')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        cur = conn.execute(f"SELECT * FROM users WHERE username='{username}' AND password='{password}'")
        if cur.fetchone():
            return "Login successful! FLAG{user_db_sqli}"
    return '''<form method="post">Username: <input name="username"><br>Password: <input name="password" type="password"><br><input type="submit"></form>'''

@app.route('/search')
def search():
    q = request.args.get('q', '')
    cur = conn.execute(f"SELECT username FROM users WHERE username LIKE '%{q}%'")
    return str([row[0] for row in cur.fetchall()])

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' in request.files:
        f = request.files['file']
        path = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
        f.save(path)
        return f"Uploaded: {path}"
    return "No file"

@app.route('/page')
def page():
    file = request.args.get('file', 'index.html')
    try:
        with open(file, 'r') as f:
            return f.read()
    except:
        return "File not found"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)