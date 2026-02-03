"""Report Viewer - Separate web application for viewing reported issues."""

from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')

def load_reports():
    """
    Load reports from SQLite database.

    Returns:
        list: List of report dictionaries
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    c.execute('SELECT id, user_id, description, timestamp, status, read_at FROM reports ORDER BY timestamp DESC')
    reports = []
    for row in c.fetchall():
        report_id, user_id, description, timestamp, status, read_at = row
        reports.append({
            'id': report_id,
            'user_id': user_id,
            'description': description,
            'timestamp': timestamp,
            'status': status,
            'read_at': read_at
        })
    conn.close()
    return reports
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'osondu' and password == 'stanley1234':
            session['user_id'] = username
            return redirect(url_for('view_reports'))
        else:
            flash('Invalid username or password')
    return render_template('report_viewer_login.html')

@app.route('/reports')
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    reports = load_reports()
    return render_template('report_viewer_reports.html', reports=reports)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_DEBUG') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)
