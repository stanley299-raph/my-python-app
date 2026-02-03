"""
Student Score Management System

A comprehensive Flask web application for managing student academic records,
including user authentication, score tracking, grading, and reporting features.

Author: Sondu Stanley
Version: 1.0.0
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, TextAreaField, SelectField, validators
from flask_wtf.csrf import CSRFProtect
import sqlite3
import json
import csv
import re
from io import StringIO, BytesIO
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

import os

def init_db():
    """Initialize the SQLite database and create tables if they don't exist."""
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()

    # Create users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    # Create students table
    c.execute('''CREATE TABLE IF NOT EXISTS students (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    student_id TEXT NOT NULL,
                    firstname TEXT NOT NULL,
                    classname TEXT NOT NULL,
                    number_of_subject INTEGER NOT NULL,
                    subjects TEXT NOT NULL,
                    scores TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, student_id)
                )''')

    # Create reports table
    c.execute('''CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    description TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    status TEXT DEFAULT 'unread',
                    read_at TEXT
                )''')

    conn.commit()
    conn.close()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')  # Use environment variable for production

# Initialize database
init_db()

def load_users():
    """
    Load user credentials from SQLite database.

    Returns:
        dict: Dictionary of username -> hashed_password pairs
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    c.execute('SELECT username, password_hash FROM users')
    users = {row[0]: row[1] for row in c.fetchall()}
    conn.close()
    return users

def save_users(users):
    """
    Save user credentials to SQLite database.

    Args:
        users (dict): Dictionary of username -> hashed_password pairs
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    c.execute('DELETE FROM users')  # Clear existing users
    for username, password_hash in users.items():
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                 (username, password_hash))
    conn.commit()
    conn.close()

def hash_password(password):
    """
    Hash a password using Werkzeug security.

    Args:
        password (str): Plain text password

    Returns:
        str: Hashed password
    """
    return generate_password_hash(password)

def check_password(hashed, password):
    """
    Verify a password against its hash.

    Args:
        hashed (str): Hashed password
        password (str): Plain text password to check

    Returns:
        bool: True if password matches hash
    """
    return check_password_hash(hashed, password)

def get_valid_score(prompt, minimum, maximum):
    """Prompts the user for a valid score within a specified range."""
    while True:
        try:
            score = int(input(prompt))
            if minimum <= score <= maximum:
                return score
            else:
                print(f"Invalid input! Enter a value between {minimum} and {maximum}.")
        except ValueError:
            print("Invalid input! Please enter a valid integer.")

def rank_students_by_average(students):
    valid_students = [
        s for s in students
        if isinstance(s, dict) and "average_marks" in s
    ]
    return sorted(valid_students, key=lambda x: x["average_marks"], reverse=True)

def calculate_positions(students_list):
    positions = {}
    class_groups = {}
    for student in students_list:
        class_name = student['class_name']
        if class_name not in class_groups:
            class_groups[class_name] = []
        class_groups[class_name].append(student)

    for class_name, class_students in class_groups.items():
        sorted_students = sorted(class_students, key=lambda x: x['average_marks'], reverse=True)
        for i, student in enumerate(sorted_students, 1):
            positions[student['student_id']] = {
                'pos': i,
                'size': len(sorted_students),
                'class': class_name
            }
    return positions

def find_student_id(user_students, student_id):
    sid = student_id.strip().lower()
    for student in user_students:
        if not isinstance(student, dict):
            continue
        if student.get("student_id", "").strip().lower() == sid:
            return student
    return None

def id_exists(user_students, student_id):
    sid = student_id.strip().lower()
    return any(isinstance(student, dict) and student.get("student_id", "").strip().lower() == sid for student in user_students)

def load_students(user_id):
    """
    Load students for a specific user from SQLite database.

    Args:
        user_id (str): The user ID to load students for

    Returns:
        dict: Dictionary of student_id -> student_data
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    c.execute('SELECT student_id, firstname, classname, number_of_subject, subjects, scores FROM students WHERE user_id = ?',
             (user_id,))
    students_data = {}
    for row in c.fetchall():
        student_id, firstname, classname, number_of_subject, subjects_str, scores_str = row
        subjects = json.loads(subjects_str) if subjects_str else []
        scores = json.loads(scores_str) if scores_str else {}
        students_data[student_id] = {
            'firstname': firstname,
            'classname': classname,
            'number_of_subject': number_of_subject,
            'subjects': subjects,
            'scores': scores
        }
    conn.close()
    return students_data

def save_student(user_id, student_id, student_data):
    """
    Save a student to SQLite database.

    Args:
        user_id (str): The user ID
        student_id (str): The student ID
        student_data (dict): The student data
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    subjects_str = json.dumps(student_data['subjects'])
    scores_str = json.dumps(student_data['scores'])
    c.execute('''INSERT OR REPLACE INTO students
                 (user_id, student_id, firstname, classname, number_of_subject, subjects, scores)
                 VALUES (?, ?, ?, ?, ?, ?, ?)''',
             (user_id, student_id, student_data['firstname'], student_data['classname'],
              student_data['number_of_subject'], subjects_str, scores_str))
    conn.commit()
    conn.close()

def delete_student(user_id, student_id):
    """
    Delete a student from SQLite database.

    Args:
        user_id (str): The user ID
        student_id (str): The student ID
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    c.execute('DELETE FROM students WHERE user_id = ? AND student_id = ?',
             (user_id, student_id))
    conn.commit()
    conn.close()

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

def save_report(report):
    """
    Save a report to SQLite database.

    Args:
        report (dict): Report dictionary
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    c.execute('INSERT INTO reports (user_id, description, timestamp, status) VALUES (?, ?, ?, ?)',
             (report['user_id'], report['description'], report['timestamp'], report['status']))
    conn.commit()
    conn.close()

def mark_report_read(report_id):
    """
    Mark a report as read by updating the read_at timestamp.

    Args:
        report_id (int): The ID of the report to mark as read
    """
    conn = sqlite3.connect('student_score.db')
    c = conn.cursor()
    c.execute('UPDATE reports SET status = ?, read_at = ? WHERE id = ?',
             ('read', datetime.now().isoformat(), report_id))
    conn.commit()
    conn.close()

@app.route('/', methods=['GET'])
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_users()
        if username in users and check_password(users[username], password):
            session['user_id'] = username
            return redirect(url_for('menu'))
        else:
            flash('Invalid username or password')
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['email'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))
        users = load_users()
        if username in users:
            flash('Email already exists')
            return redirect(url_for('signup'))
        users[username] = hash_password(password)
        save_users(users)
        flash('Account created successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('home'))

@app.route('/menu')
def menu():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('menu.html')

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        student_id = request.form['student_id']
        firstname = request.form['firstname']
        classname = request.form['classname']
        number_of_subject = int(request.form['number_of_subject'])

        # Improved subject parsing: handle comma, space, or newline separated
        subjects_input = request.form['subjects']
        subjects = [s.strip() for s in re.split(r'[,\s\n]+', subjects_input.strip()) if s.strip()]

        # Validation: Check if number of subjects matches
        if len(subjects) != number_of_subject:
            flash("Number of subjects does not match the subjects provided.", "error")
            return redirect(url_for('add_student'))

        # Validation: Check for duplicate subjects
        if len(set(subjects)) != len(subjects):
            flash("Duplicate subjects are not allowed.", "error")
            return redirect(url_for('add_student'))

        user_id = session['user_id']
        student_data = {
            'firstname': firstname,
            'classname': classname,
            'number_of_subject': number_of_subject,
            'subjects': subjects,
            'scores': {}
        }

        save_student(user_id, student_id, student_data)
        flash('Student added successfully! Now enter scores for each subject.', 'success')
        return redirect(url_for('enter_scores', student_id=student_id))

    return render_template('add_student.html')

@app.route('/view_students')
def view_students():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_students = load_students(user_id)

    # Transform data to match template expectations
    students_list = []
    total_average = 0
    grade_a_count = 0
    pass_count = 0

    for student_id, student_data in user_students.items():
        # Calculate average marks from overall_mark
        scores = student_data.get('scores', {})
        if scores:
            overall_marks = []
            for subj_data in scores.values():
                if isinstance(subj_data, dict):
                    # New format: detailed score object
                    overall_marks.append(subj_data.get('overall_mark', 0))
                elif isinstance(subj_data, (int, float)):
                    # Old format: simple number
                    overall_marks.append(float(subj_data))
            average_marks = sum(overall_marks) / len(overall_marks) if overall_marks else 0
        else:
            average_marks = 0

        # Determine grade
        if average_marks >= 90:
            grade = 'A'
            grade_a_count += 1
        elif average_marks >= 80:
            grade = 'B'
        elif average_marks >= 70:
            grade = 'C'
        elif average_marks >= 60:
            grade = 'D'
        else:
            grade = 'F'

        # Determine status
        status = 'Pass' if average_marks >= 60 else 'Fail'
        if status == 'Pass':
            pass_count += 1

        total_average += average_marks

        students_list.append({
            'first_name': student_data.get('firstname', ''),
            'student_id': student_id,
            'class_name': student_data.get('classname', ''),
            'subjects': {
                subj: {
                    'overall_mark': subj_data.get('overall_mark', 0) if isinstance(subj_data, dict) else 0,
                    'grade': subj_data.get('grade', grade) if isinstance(subj_data, dict) else grade,
                    'status': status,
                    'tests': [subj_data.get('first_test', 0), subj_data.get('second_test', 0), subj_data.get('third_test', 0)] if isinstance(subj_data, dict) else [],
                    'cbt': subj_data.get('objective', 0) if isinstance(subj_data, dict) else 0,
                    'theory_exam': subj_data.get('theory', 0) if isinstance(subj_data, dict) else 0,
                    'total_exam': subj_data.get('total_exam', 0) if isinstance(subj_data, dict) else 0,
                    'total_test': subj_data.get('total_test', 0) if isinstance(subj_data, dict) else 0
                }
                for subj, subj_data in scores.items()
            },
            'average_marks': average_marks,
            'Grade': grade,
            'Status': status
        })

    # Calculate overall statistics
    overall_average = total_average / len(students_list) if students_list else 0

    # Get unique classes for filter dropdown
    classes = list(set(student['class_name'] for student in students_list))
    positions = calculate_positions(students_list)

    return render_template('view_students.html',
                         students=students_list,
                         total_students=len(students_list),
                         grade_a_count=grade_a_count,
                         pass_count=pass_count,
                         overall_average=overall_average,
                         classes=classes,
                         positions=positions)

@app.route('/edit_student', methods=['GET', 'POST'])
def edit_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_students = load_students(user_id)

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        if student_id and student_id in user_students:
            # Update student data
            student_data = user_students[student_id]
            student_data['firstname'] = request.form.get('firstname', '')
            student_data['classname'] = request.form.get('classname', '')
            student_data['number_of_subject'] = int(request.form.get('number_of_subject', 0))
            student_data['subjects'] = [s.strip() for s in re.split(r'[,\s]+', request.form.get('subjects', '')) if s.strip()]

            save_student(user_id, student_id, student_data)
            flash('Student updated successfully!')
            return redirect(url_for('view_students'))
        else:
            flash('Student not found.')

    # For GET request, show form to select student
    student_id = request.args.get('student_id')
    if student_id and student_id in user_students:
        student = user_students[student_id]
        return render_template('edit_student.html', student=student, student_id=student_id, students=user_students)
    else:
        return render_template('edit_student.html', students=user_students)

@app.route('/delete_student', methods=['GET', 'POST'])
def delete_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_students = load_students(user_id)

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        if student_id and student_id in user_students:
            delete_student(user_id, student_id)
            flash('Student deleted successfully!')
            return redirect(url_for('view_students'))
        else:
            flash('Student not found.')

    return render_template('delete_student.html', students=user_students)

@app.route('/search_student', methods=['GET', 'POST'])
def search_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_students = load_students(user_id)

    search_results = []
    search_query = ''

    if request.method == 'POST':
        search_query = request.form.get('search_query', '').strip().lower()

        if search_query:
            for student_id, student_data in user_students.items():
                if (search_query in student_id.lower() or
                    search_query in student_data.get('firstname', '').lower() or
                    search_query in student_data.get('classname', '').lower()):
                    # Calculate average marks from overall_mark
                    scores = student_data.get('scores', {})
                    if scores:
                        overall_marks = [subj_data.get('overall_mark', 0) for subj_data in scores.values() if isinstance(subj_data, dict)]
                        average_marks = sum(overall_marks) / len(overall_marks) if overall_marks else 0
                    else:
                        average_marks = 0

                    # Determine grade
                    if average_marks >= 90:
                        grade = 'A'
                    elif average_marks >= 80:
                        grade = 'B'
                    elif average_marks >= 70:
                        grade = 'C'
                    elif average_marks >= 60:
                        grade = 'D'
                    else:
                        grade = 'F'

                    # Determine status
                    status = 'Pass' if average_marks >= 60 else 'Fail'

                    search_results.append({
                        'first_name': student_data.get('firstname', ''),
                        'student_id': student_id,
                        'class_name': student_data.get('classname', ''),
                        'subjects': {subj: subj_data.get('overall_mark', 0) for subj, subj_data in scores.items() if isinstance(subj_data, dict)},
                        'average_marks': average_marks,
                        'Grade': grade,
                        'Status': status
                    })

    return render_template('search_student.html', students=search_results, search_query=search_query)

@app.route('/rank_students')
def rank_students():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_students = load_students(user_id)

    class_filter = request.args.get('class', '').strip()

    # Transform data and calculate averages
    students_list = []
    for student_id, student_data in user_students.items():
        scores = student_data.get('scores', {})
        if scores:
            overall_marks = []
            for subj_data in scores.values():
                if isinstance(subj_data, dict):
                    # New format: detailed score object
                    overall_marks.append(subj_data.get('overall_mark', 0))
                elif isinstance(subj_data, (int, float)):
                    # Old format: simple number
                    overall_marks.append(float(subj_data))
            average_marks = sum(overall_marks) / len(overall_marks) if overall_marks else 0
        else:
            average_marks = 0

        # Determine grade
        if average_marks >= 90:
            grade = 'A'
        elif average_marks >= 80:
            grade = 'B'
        elif average_marks >= 70:
            grade = 'C'
        elif average_marks >= 60:
            grade = 'D'
        else:
            grade = 'F'

        # Determine status
        status = 'Pass' if average_marks >= 60 else 'Fail'

        students_list.append({
            'first_name': student_data.get('firstname', ''),
            'student_id': student_id,
            'class_name': student_data.get('classname', ''),
            'subjects': {subj: subj_data.get('overall_mark', 0) for subj, subj_data in scores.items() if isinstance(subj_data, dict)},
            'average_marks': average_marks,
            'Grade': grade,
            'Status': status
        })

    # Filter by class if specified
    if class_filter:
        students_list = [s for s in students_list if s['class_name'].lower() == class_filter.lower()]

    # Group by class and sort within each class
    ranked = {}
    for student in students_list:
        class_name = student['class_name']
        if class_name not in ranked:
            ranked[class_name] = []
        ranked[class_name].append(student)

    for class_name in ranked:
        ranked[class_name].sort(key=lambda x: x['average_marks'], reverse=True)

    return render_template('rank_students.html', ranked=ranked, class_filter=class_filter)

@app.route('/enter_scores', methods=['GET', 'POST'])
def enter_scores():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    student_id = request.args.get('student_id')
    user_id = session['user_id']

    if not student_id or user_id not in students or student_id not in students[user_id]:
        flash('Student not found.')
        return redirect(url_for('menu'))

    student = students[user_id][student_id]

    if request.method == 'POST':
        scores = {}
        invalid_scores = []
        for subject in student['subjects']:
            subj_key = subject.replace(' ', '_')
            subject_scores = {}
            try:
                first_test = float(request.form.get(f'first_test_{subj_key}', 0))
                second_test = float(request.form.get(f'second_test_{subj_key}', 0))
                third_test = float(request.form.get(f'third_test_{subj_key}', 0))
                objective = float(request.form.get(f'objective_{subj_key}', 0))
                theory = float(request.form.get(f'theory_{subj_key}', 0))

                # Validate ranges
                if not (0 <= first_test <= 10): invalid_scores.append(f'{subject}: First test must be 0-10')
                if not (0 <= second_test <= 10): invalid_scores.append(f'{subject}: Second test must be 0-10')
                if not (0 <= third_test <= 10): invalid_scores.append(f'{subject}: Third test must be 0-10')
                if not (0 <= objective <= 30): invalid_scores.append(f'{subject}: Objective must be 0-30')
                if not (0 <= theory <= 40): invalid_scores.append(f'{subject}: Theory must be 0-40')

                # Calculate totals and grades
                calculated_total_test = first_test + second_test + third_test
                calculated_total_exam = objective + theory
                calculated_overall_mark = calculated_total_test + calculated_total_exam
                if not (0 <= calculated_total_test <= 30): invalid_scores.append(f'{subject}: Total test must be 0-30')
                if not (0 <= calculated_total_exam <= 70): invalid_scores.append(f'{subject}: Total exam must be 0-70')
                if not (0 <= calculated_overall_mark <= 100): invalid_scores.append(f'{subject}: Overall mark must be 0-100')

                # Determine test grade based on total test
                if calculated_total_test >= 27:
                    calculated_test_grade = 'A'
                elif calculated_total_test >= 24:
                    calculated_test_grade = 'B'
                elif calculated_total_test >= 21:
                    calculated_test_grade = 'C'
                elif calculated_total_test >= 18:
                    calculated_test_grade = 'D'
                else:
                    calculated_test_grade = 'F'

                # Determine overall grade based on overall mark
                if calculated_overall_mark >= 90:
                    calculated_grade = 'A'
                elif calculated_overall_mark >= 80:
                    calculated_grade = 'B'
                elif calculated_overall_mark >= 70:
                    calculated_grade = 'C'
                elif calculated_overall_mark >= 60:
                    calculated_grade = 'D'
                else:
                    calculated_grade = 'F'

                subject_scores = {
                    'first_test': first_test,
                    'second_test': second_test,
                    'third_test': third_test,
                    'total_test': calculated_total_test,
                    'test_grade': calculated_test_grade,
                    'objective': objective,
                    'theory': theory,
                    'total_exam': calculated_total_exam,
                    'overall_mark': calculated_overall_mark,
                    'grade': calculated_grade
                }
                scores[subject] = subject_scores
            except ValueError:
                invalid_scores.append(f'{subject}: Invalid number format')

        if invalid_scores:
            for error in invalid_scores:
                flash(error, 'error')
            return redirect(url_for('enter_scores', student_id=student_id))

        student['scores'] = scores
        save_to_json(students)
        flash('Scores entered successfully!')
        return redirect(url_for('menu'))

    return render_template('enter_scores.html', student=student, student_id=student_id)

@app.route('/student_report')
def student_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    student_id = request.args.get('student_id')
    user_id = session['user_id']

    user_students = load_students(user_id)
    if not student_id or student_id not in user_students:
        flash('Student not found.')
        return redirect(url_for('view_students'))

    student_data = user_students[student_id]
    scores = student_data.get('scores', {})

    if scores:
        overall_marks = [subj_data.get('overall_mark', 0) for subj_data in scores.values() if isinstance(subj_data, dict)]
        average_marks = sum(overall_marks) / len(overall_marks) if overall_marks else 0
    else:
        average_marks = 0

    if average_marks >= 90:
        grade = 'A'
    elif average_marks >= 80:
        grade = 'B'
    elif average_marks >= 70:
        grade = 'C'
    elif average_marks >= 60:
        grade = 'D'
    else:
        grade = 'F'

    status = 'Pass' if average_marks >= 60 else 'Fail'

    # Restructure subjects as dictionary with score data
    subjects_with_scores = {}
    for subject in student_data.get('subjects', []):
        subjects_with_scores[subject] = scores.get(subject, {})

    # Build positions across this user's students
    students_list = []
    for sid, sdata in user_students.items():
        sscores = sdata.get('scores', {})
        if sscores:
            overall_marks = [subj_data.get('overall_mark', 0) for subj_data in sscores.values() if isinstance(subj_data, dict)]
            avg_marks = sum(overall_marks) / len(overall_marks) if overall_marks else 0
        else:
            avg_marks = 0
        students_list.append({
            'first_name': sdata.get('firstname', ''),
            'student_id': sid,
            'class_name': sdata.get('classname', ''),
            'subjects': sscores,
            'average_marks': avg_marks
        })
    positions = calculate_positions(students_list)

    student = {
        'first_name': student_data.get('firstname', ''),
        'student_id': student_id,
        'class_name': student_data.get('classname', ''),
        'number_of_subject': student_data.get('number_of_subject', 0),
        'subjects': subjects_with_scores,  # Now a dict: subject -> score_data
        'average_marks': average_marks,
        'Grade': grade,
        'Status': status
    }

    return render_template('student_report.html', student=student, position=positions.get(student_id))

@app.route('/all_students_report')
def all_students_report():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_students = load_students(user_id)
    class_filter = request.args.get('class', '').strip()
    student_id_filter = request.args.get('student_id', '').strip()

    # Transform data to match template expectations
    students_list = []
    for student_id, student_data in user_students.items():
        # Calculate average marks from overall_mark
        scores = student_data.get('scores', {})
        if scores:
            overall_marks = []
            for subj_data in scores.values():
                if isinstance(subj_data, dict):
                    # New format: detailed score object
                    overall_marks.append(subj_data.get('overall_mark', 0))
                elif isinstance(subj_data, (int, float)):
                    # Old format: simple number
                    overall_marks.append(float(subj_data))
            average_marks = sum(overall_marks) / len(overall_marks) if overall_marks else 0
        else:
            average_marks = 0

        # Determine grade
        if average_marks >= 90:
            grade = 'A'
        elif average_marks >= 80:
            grade = 'B'
        elif average_marks >= 70:
            grade = 'C'
        elif average_marks >= 60:
            grade = 'D'
        else:
            grade = 'F'

        # Determine status
        status = 'Pass' if average_marks >= 60 else 'Fail'

        students_list.append({
            'first_name': student_data.get('firstname', ''),
            'student_id': student_id,
            'class_name': student_data.get('classname', ''),
            'subjects': {
                subj: {
                    'overall_mark': subj_data.get('overall_mark', 0) if isinstance(subj_data, dict) else 0,
                    'grade': subj_data.get('grade', grade) if isinstance(subj_data, dict) else grade,
                    'status': status,
                    'tests': [subj_data.get('first_test', 0), subj_data.get('second_test', 0), subj_data.get('third_test', 0)] if isinstance(subj_data, dict) else [],
                    'cbt': subj_data.get('objective', 0) if isinstance(subj_data, dict) else 0,
                    'theory_exam': subj_data.get('theory', 0) if isinstance(subj_data, dict) else 0,
                    'total_exam': subj_data.get('total_exam', 0) if isinstance(subj_data, dict) else 0,
                    'total_test': subj_data.get('total_test', 0) if isinstance(subj_data, dict) else 0
                }
                for subj, subj_data in scores.items()
            },
            'average_marks': average_marks,
            'Grade': grade,
            'Status': status
        })

    # Apply filters (case-insensitive)
    if class_filter:
        students_list = [
            s for s in students_list
            if s.get('class_name', '').lower() == class_filter.lower()
        ]
    if student_id_filter:
        students_list = [
            s for s in students_list
            if s.get('student_id', '').lower() == student_id_filter.lower()
        ]

    positions = calculate_positions(students_list)

    return render_template(
        'all_students_report.html',
        students=students_list,
        positions=positions,
        now=datetime.now().strftime("%Y-%m-%d %H:%M"),
        class_filter=class_filter,
        student_id_filter=student_id_filter
    )

@app.route('/reports/all_students')
def reports_all_students():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('all_students_report'))

@app.route('/reports/export_csv')
def reports_export_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # For now, just redirect to all_students_report
    return redirect(url_for('all_students_report'))

@app.route('/rank/export_csv')
def export_rank_csv():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Placeholder: re-use existing CSV export until rank-specific export is implemented
    return redirect(url_for('reports_export_csv', **request.args))

@app.route('/rank/export_xlsx')
def export_rank_xlsx():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    flash('Rank XLSX export is not implemented yet.', 'info')
    return redirect(url_for('rank_students', **request.args))

@app.route('/report_issue', methods=['GET', 'POST'])
def report_issue():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        issue_description = request.form.get('issue_description', '').strip()
        if issue_description:
            report = {
                'user_id': session['user_id'],
                'description': issue_description,
                'timestamp': datetime.now().isoformat(),
                'status': 'unread'
            }
            save_report(report)
            flash('Issue reported successfully! Thank you for your feedback.', 'success')
            return redirect(url_for('menu'))
        else:
            flash('Please describe the issue.', 'error')

    return render_template('report_issue.html')

@app.route('/view_reports')
def view_reports():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Only allow admin user to view reports
    if session['user_id'] != 'osondu':
        flash('Access denied. Only administrators can view reports.', 'error')
        return redirect(url_for('menu'))

    reports = load_reports()
    return render_template('view_reports.html', reports=reports)

@app.route('/mark_report_read/<int:report_id>')
def mark_report_read_route(report_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Only allow admin user to mark reports as read
    if session['user_id'] != 'osondu':
        flash('Access denied. Only administrators can mark reports as read.', 'error')
        return redirect(url_for('view_reports'))

    mark_report_read(report_id)
    flash('Report marked as read.', 'success')
    return redirect(url_for('view_reports'))

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG') == '1'
    app.run(host='0.0.0.0', port=port, debug=debug)


