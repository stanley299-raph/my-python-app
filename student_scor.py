"""
Student Score Management System

A comprehensive Flask web application for managing student academic records,
including user authentication, score tracking, grading, and reporting features.

Author: AI Assistant
Version: 1.0.0
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
import json
import csv
from io import StringIO, BytesIO
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')  # Use environment variable for production

def load_users():
    """
    Load user credentials from JSON file.

    Returns:
        dict: Dictionary of username -> hashed_password pairs
    """
    try:
        with open("users.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    """
    Save user credentials to JSON file.

    Args:
        users (dict): Dictionary of username -> hashed_password pairs
    """
    with open("users.json", "w") as f:
        json.dump(users, f)

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

def rank_students(students):
    valid_students = [
        s for s in students
        if isinstance(s, dict) and "average_marks" in s
    ]
    return sorted(valid_students, key=lambda x: x["average_marks"], reverse=True)

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

def save_to_json(students, filename="students.json"):
    with open(filename, "w") as file:
        json.dump(students, file, indent=4)

def load_from_json(filename="students.json"):
    try:
        with open(filename, "r") as file:
            data = json.load(file)
            if not isinstance(data, dict):
                return {}
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

students = load_from_json()

@app.route('/', methods=['GET', 'POST'])
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
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('Passwords do not match')
            return redirect(url_for('signup'))
        users = load_users()
        if username in users:
            flash('Username already exists')
            return redirect(url_for('signup'))
        users[username] = hash_password(password)
        save_users(users)
        flash('Account created successfully. Please log in.')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/menu')
def menu():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('menu.html')

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user_students = students.get(user_id, [])
    if request.method == 'POST':
        student_id = request.form['student_id'].strip()
        if find_student_id(user_students, student_id):
            flash('Student ID already exists!')
            return redirect(url_for('add_student'))
        firstname = request.form['firstname'].strip()
        classname = request.form['classname'].strip()
        number_of_subject = int(request.form['number_of_subject'])
        subjects_str = request.form['subjects']
        subjects = [s.strip() for s in subjects_str.split(",") if s.strip()]
        if len(subjects) != number_of_subject:
            flash('Number of subjects does not match the subjects provided.')
            return redirect(url_for('add_student'))

        # Store in session and redirect to enter scores
        session['student_id'] = student_id
        session['firstname'] = firstname
        session['classname'] = classname
        session['number_of_subject'] = number_of_subject
        session['subjects'] = subjects
        return redirect(url_for('enter_scores'))
    return render_template('add_student.html')

@app.route('/enter_scores', methods=['GET', 'POST'])
def enter_scores():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if 'student_id' not in session:
        return redirect(url_for('add_student'))
    if request.method == 'POST':
        subjects = session['subjects']
        subject_data = {}
        alltogether = 0
        # Validate and collect per-subject scores
        for i, subject in enumerate(subjects):
            try:
                test1 = int(request.form[f'test1_{i}'])
                test2 = int(request.form[f'test2_{i}'])
                test3 = int(request.form[f'test3_{i}'])
            except (KeyError, ValueError):
                flash(f'Invalid or missing test scores for subject "{subject}".')
                return redirect(url_for('enter_scores'))
            if not (0 <= test1 <= 10 and 0 <= test2 <= 10 and 0 <= test3 <= 10):
                flash(f'Tests for "{subject}" must be between 0 and 10.')
                return redirect(url_for('enter_scores'))

            total_test = test1 + test2 + test3

            try:
                obj_exam = int(request.form[f'obj_exam_{i}'])
                theory_exam = int(request.form[f'theory_exam_{i}'])
            except (KeyError, ValueError):
                flash(f'Invalid or missing exam scores for subject "{subject}".')
                return redirect(url_for('enter_scores'))
            if not (0 <= obj_exam <= 30 and 0 <= theory_exam <= 40):
                flash(f'Exam scores for "{subject}" must be within CBT 0-30 and Theory 0-40.')
                return redirect(url_for('enter_scores'))

            total_exam = obj_exam + theory_exam
            subject_total = total_test + total_exam

            # Subject grade and status
            if subject_total >= 75:
                sub_grade = 'A'
            elif subject_total >= 60:
                sub_grade = 'B'
            elif subject_total >= 50:
                sub_grade = 'C'
            elif subject_total >= 40:
                sub_grade = 'D'
            else:
                sub_grade = 'F'
            sub_status = 'Passed' if subject_total >= 50 else 'Failed'

            subject_data[subject] = {
                "tests": [test1, test2, test3],
                "total_test": total_test,
                "cbt": obj_exam,
                "theory_exam": theory_exam,
                "total_exam": total_exam,
                "overall_mark": subject_total,
                "grade": sub_grade,
                "status": sub_status
            }
            alltogether += subject_total

        number = len(subjects)
        average_per_subject = (alltogether / number) if number > 0 else 0

        # Overall grade and status based on average per subject
        if average_per_subject >= 75:
            grade = 'A'
        elif average_per_subject >= 60:
            grade = 'B'
        elif average_per_subject >= 50:
            grade = 'C'
        elif average_per_subject >= 40:
            grade = 'D'
        else:
            grade = 'F'
        status = 'Passed' if average_per_subject >= 50 else 'Failed'

        user_id = session.get('user_id')
        if user_id not in students:
            students[user_id] = []
        student = {
            "student_id": session['student_id'],
            "first_name": session['firstname'],
            "class_name": session['classname'],
            "number_of_subject": session['number_of_subject'],
            "subjects": subject_data,
            "total_marks": alltogether,
            "average_marks": average_per_subject,
            "Grade": grade,
            "Status": status
        }
        students[user_id].append(student)
        save_to_json(students)
        # Clear session
        session.pop('student_id', None)
        session.pop('firstname', None)
        session.pop('classname', None)
        session.pop('number_of_subject', None)
        session.pop('subjects', None)
        flash('Student added successfully!')
        return redirect(url_for('menu'))
    return render_template('enter_scores.html')

@app.route('/view_students')
def view_students():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user_students = students.get(user_id, [])
    return render_template('view_students.html', students=user_students)

@app.route('/edit_student', methods=['GET', 'POST'])
def edit_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user_students = students.get(user_id, [])
    if request.method == 'POST':
        student_id = request.form['student_id'].strip()
        student = find_student_id(user_students, student_id)
        if not student:
            flash('Student not found.')
            return redirect(url_for('edit_student'))
        student['first_name'] = request.form['firstname'].strip()
        student['class_name'] = request.form['classname'].strip()
        student['Status'] = request.form['status'].strip()
        save_to_json(students)
        flash('Student updated successfully!')
        return redirect(url_for('menu'))
    return render_template('edit_student.html')

@app.route('/delete_student', methods=['GET', 'POST'])
def delete_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user_students = students.get(user_id, [])
    if request.method == 'POST':
        student_id = request.form['student_id'].strip()
        student = find_student_id(user_students, student_id)
        if not student:
            flash('Student not found.')
            return redirect(url_for('delete_student'))
        user_students.remove(student)
        save_to_json(students)
        flash(f'Student {student_id} deleted successfully.')
        return redirect(url_for('menu'))
    return render_template('delete_student.html')

@app.route('/search_student', methods=['GET', 'POST'])
def search_student():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user_students = students.get(user_id, [])
    student = None
    if request.method == 'POST':
        student_id = request.form['student_id'].strip()
        student = find_student_id(user_students, student_id)
        if not student:
            flash('Student not found.')
    return render_template('search_student.html', student=student)

@app.route('/rank_students')
def rank_students_route():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user_students = students.get(user_id, [])
    # Optional filter by class
    class_filter = request.args.get('class')
    # Group students by class and sort each group by average_marks descending
    grouped = {}
    for s in user_students:
        if not isinstance(s, dict) or 'average_marks' not in s:
            continue
        cls = s.get('class_name', 'Unknown')
        grouped.setdefault(cls, []).append(s)
    for cls in grouped:
        grouped[cls].sort(key=lambda x: x.get('average_marks', 0), reverse=True)
    if class_filter:
        grouped = {k: v for k, v in grouped.items() if k.strip().lower() == class_filter.strip().lower()}
    return render_template('rank_students.html', ranked=grouped, class_filter=class_filter or '')

@app.route('/reports/export_rank_csv')
def export_rank_csv():
    """Export ranking as CSV. Optional query param 'class' filters by class."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    class_filter = request.args.get('class')
    # Build grouped/sorted data
    grouped = {}
    for user_id, user_students in students.items():
        for s in user_students:
            if not isinstance(s, dict) or 'average_marks' not in s:
                continue
            cls = s.get('class_name', 'Unknown')
            grouped.setdefault(cls, []).append(s)
    for cls in grouped:
        grouped[cls].sort(key=lambda x: x.get('average_marks', 0), reverse=True)
    if class_filter:
        grouped = {k: v for k, v in grouped.items() if k.strip().lower() == class_filter.strip().lower()}

    # Create CSV
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['class_name', 'position', 'student_id', 'first_name', 'average_marks', 'Grade', 'Status'])
    for cls, lst in grouped.items():
        for pos, s in enumerate(lst, start=1):
            writer.writerow([cls, pos, s.get('student_id',''), s.get('first_name',''), s.get('average_marks',''), s.get('Grade',''), s.get('Status','')])
    output = si.getvalue()
    return (output, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="rankings.csv"'
    })

@app.route('/reports/export_rank_xlsx')
def export_rank_xlsx():
    """Export ranking as XLSX. Optional query param 'class' filters by class."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    class_filter = request.args.get('class')
    # Build grouped/sorted data
    grouped = {}
    for user_id, user_students in students.items():
        for s in user_students:
            if not isinstance(s, dict) or 'average_marks' not in s:
                continue
            cls = s.get('class_name', 'Unknown')
            grouped.setdefault(cls, []).append(s)
    for cls in grouped:
        grouped[cls].sort(key=lambda x: x.get('average_marks', 0), reverse=True)
    if class_filter:
        grouped = {k: v for k, v in grouped.items() if k.strip().lower() == class_filter.strip().lower()}

    # Create XLSX in memory
    try:
        from openpyxl import Workbook
        from io import BytesIO
    except Exception as e:
        flash('XLSX export requires openpyxl.')
        return redirect(url_for('rank_students_route'))

    wb = Workbook()
    ws = wb.active
    ws.title = 'Rankings'
    headers = ['class_name', 'position', 'student_id', 'first_name', 'average_marks', 'Grade', 'Status']
    ws.append(headers)

    # Fill rows
    for cls, lst in grouped.items():
        for pos, s in enumerate(lst, start=1):
            ws.append([cls, pos, s.get('student_id',''), s.get('first_name',''), s.get('average_marks',''), s.get('Grade',''), s.get('Status','')])

    # Styling: bold headers and freeze panes
    try:
        from openpyxl.styles import Font, Alignment
        from openpyxl.utils import get_column_letter
    except Exception:
        Font = None
        Alignment = None
        get_column_letter = None

    if Font:
        for col_idx, header in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=col_idx)
            cell.font = Font(bold=True)
            cell.alignment = Alignment(horizontal='center')
        ws.freeze_panes = 'A2'

    # Auto-fit column widths based on max length in each column
    if get_column_letter:
        for col_idx in range(1, ws.max_column + 1):
            col_letter = get_column_letter(col_idx)
            max_len = 0
            for row in ws.iter_rows(min_row=1, min_col=col_idx, max_col=col_idx, max_row=ws.max_row):
                cell = row[0]
                val = cell.value
                if val is None:
                    continue
                l = len(str(val))
                if l > max_len:
                    max_len = l
            adjusted_width = (max_len + 2)
            if adjusted_width < 8:
                adjusted_width = 8
            if adjusted_width > 50:
                adjusted_width = 50
            ws.column_dimensions[col_letter].width = adjusted_width

    bio = BytesIO()
    wb.save(bio)
    bio.seek(0)
    return send_file(bio, as_attachment=True, download_name='rankings.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

@app.route('/student/<path:student_id>')
def student_report(student_id):
    """Show printable per-subject report for a single student, with class position."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    user_students = students.get(user_id, [])
    student = find_student_id(user_students, student_id)
    if not student:
        flash('Student not found.')
        return redirect(url_for('view_students'))

    # Compute class-wise positions across user's students
    grouped = {}
    for s in user_students:
        if not isinstance(s, dict) or 'average_marks' not in s:
            continue
        cls = s.get('class_name', 'Unknown')
        grouped.setdefault(cls, []).append(s)
    for cls in grouped:
        grouped[cls].sort(key=lambda x: x.get('average_marks', 0), reverse=True)
    positions = {}
    for cls, lst in grouped.items():
        size = len(lst)
        for pos, s in enumerate(lst, start=1):
            positions[s.get('student_id','')] = {'pos': pos, 'size': size, 'class': cls}

    pos = positions.get(student.get('student_id',''))
    return render_template('student_report.html', student=student, position=pos)

@app.route('/reports/all_students')
def all_students_report():
    """Printable report for all students with optional filters."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    from datetime import datetime
    class_filter = request.args.get('class')
    student_id_filter = request.args.get('student_id')

    def _filter(studs):
        all_students = []
        for user_students in studs.values():
            all_students.extend(user_students)
        results = all_students
        if class_filter:
            results = [s for s in results if s.get('class_name','').strip().lower() == class_filter.strip().lower()]
        if student_id_filter:
            results = [s for s in results if s.get('student_id','').strip().lower() == student_id_filter.strip().lower()]
        return results

    filtered = _filter(students)
    # Compute class-wise ranking positions for filtered set
    grouped = {}
    for s in filtered:
        if not isinstance(s, dict) or 'average_marks' not in s:
            continue
        cls = s.get('class_name', 'Unknown')
        grouped.setdefault(cls, []).append(s)
    for cls in grouped:
        grouped[cls].sort(key=lambda x: x.get('average_marks', 0), reverse=True)
    positions = {}
    for cls, lst in grouped.items():
        size = len(lst)
        for pos, s in enumerate(lst, start=1):
            positions[s.get('student_id','')] = {'pos': pos, 'size': size, 'class': cls}

    return render_template('all_students_report.html', students=filtered, now=datetime.now().strftime('%Y-%m-%d %H:%M'), class_filter=class_filter or '', student_id_filter=student_id_filter or '', positions=positions)

import csv
from io import StringIO

@app.route('/reports/export_csv')
def export_csv():
    """Export a summary CSV (one row per student). Supports optional filters via query params."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    class_filter = request.args.get('class')
    student_id_filter = request.args.get('student_id')

    def _filter(studs):
        all_students = []
        for user_students in studs.values():
            all_students.extend(user_students)
        results = all_students
        if class_filter:
            results = [s for s in results if s.get('class_name','').strip().lower() == class_filter.strip().lower()]
        if student_id_filter:
            results = [s for s in results if s.get('student_id','').strip().lower() == student_id_filter.strip().lower()]
        return results

    filtered = _filter(students)

    # Compute positions within filtered set
    grouped = {}
    for s in filtered:
        if not isinstance(s, dict) or 'average_marks' not in s:
            continue
        cls = s.get('class_name', 'Unknown')
        grouped.setdefault(cls, []).append(s)
    for cls in grouped:
        grouped[cls].sort(key=lambda x: x.get('average_marks', 0), reverse=True)
    positions = {}
    for cls, lst in grouped.items():
        size = len(lst)
        for pos, s in enumerate(lst, start=1):
            positions[s.get('student_id','')] = {'pos': pos, 'size': size}

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['student_id', 'first_name', 'class_name', 'number_of_subject', 'total_marks', 'average_marks', 'Grade', 'Status', 'position_in_class', 'class_size'])
    for s in filtered:
        p = positions.get(s.get('student_id',''), {})
        writer.writerow([s.get('student_id',''), s.get('first_name',''), s.get('class_name',''), s.get('number_of_subject',''), s.get('total_marks',''), s.get('average_marks',''), s.get('Grade',''), s.get('Status',''), p.get('pos',''), p.get('size','')])
    output = si.getvalue()
    return (output, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="students_summary.csv"'
    })

@app.route('/reports/export_detailed_csv')
def export_detailed_csv():
    """Export detailed CSV (one row per student per subject). Supports optional filters via query params."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    class_filter = request.args.get('class')
    student_id_filter = request.args.get('student_id')

    def _filter(studs):
        all_students = []
        for user_students in studs.values():
            all_students.extend(user_students)
        results = all_students
        if class_filter:
            results = [s for s in results if s.get('class_name','').strip().lower() == class_filter.strip().lower()]
        if student_id_filter:
            results = [s for s in results if s.get('student_id','').strip().lower() == student_id_filter.strip().lower()]
        return results

    filtered = _filter(students)

    # Compute positions for filtered set
    grouped = {}
    for s in filtered:
        if not isinstance(s, dict) or 'average_marks' not in s:
            continue
        cls = s.get('class_name', 'Unknown')
        grouped.setdefault(cls, []).append(s)
    for cls in grouped:
        grouped[cls].sort(key=lambda x: x.get('average_marks', 0), reverse=True)
    positions = {}
    for cls, lst in grouped.items():
        size = len(lst)
        for pos, s in enumerate(lst, start=1):
            positions[s.get('student_id','')] = {'pos': pos, 'size': size}

    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['student_id','first_name','class_name','subject','test1','test2','test3','total_test','cbt','theory_exam','total_exam','overall_mark','grade','status','position_in_class','class_size'])
    for s in filtered:
        p = positions.get(s.get('student_id',''), {})
        for subject, v in s.get('subjects',{}).items():
            t = v.get('tests', [])
            test1 = t[0] if isinstance(t, (list,tuple)) and len(t) > 0 else ''
            test2 = t[1] if isinstance(t, (list,tuple)) and len(t) > 1 else ''
            test3 = t[2] if isinstance(t, (list,tuple)) and len(t) > 2 else ''
            writer.writerow([s.get('student_id',''), s.get('first_name',''), s.get('class_name',''), subject, test1, test2, test3, v.get('total_test', ''), v.get('cbt',''), v.get('theory_exam',''), v.get('total_exam',''), v.get('overall_mark', v.get('total','')), v.get('grade',''), v.get('status',''), p.get('pos',''), p.get('size','')])
    output = si.getvalue()
    return (output, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="students_detailed.csv"'
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
