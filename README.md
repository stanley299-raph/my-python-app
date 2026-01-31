# Student Score Management System

A Flask-based web application for managing student scores with user authentication, data persistence, and comprehensive reporting features.

## Features

- **User Authentication**: Secure signup and login system with password hashing
- **Student Management**: Add, view, edit, delete, and search students
- **Score Entry**: Detailed score tracking with tests and exams per subject
- **Grading System**: Automatic grade calculation based on performance
- **Ranking System**: Class-wise student rankings
- **Reports**: Comprehensive reporting with CSV and Excel export capabilities
- **Data Isolation**: Each user has their own private student database

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   pip install flask werkzeug openpyxl requests
   ```
3. Run the application:
   ```bash
   python student_scor.py
   ```
4. Open http://127.0.0.1:5000 in your browser

## Usage

1. **Sign Up**: Create a new account
2. **Login**: Access your dashboard
3. **Add Students**: Enter student information and scores
4. **Manage Data**: View, edit, search, and delete student records
5. **Generate Reports**: Export rankings and detailed reports

## Project Structure

```
├── student_scor.py          # Main Flask application
├── templates/               # HTML templates
│   ├── login.html
│   ├── signup.html
│   ├── menu.html
│   └── ...
├── static/                  # Static files (CSS, JS)
├── users.json               # User credentials (auto-generated)
├── students.json            # Student data (auto-generated)
└── test_*.py               # Test scripts
```

## Security Features

- Password hashing using Werkzeug
- Session-based authentication
- User data isolation
- Input validation and sanitization

## Technologies Used

- **Backend**: Flask (Python web framework)
- **Frontend**: HTML, CSS, Jinja2 templates
- **Data Storage**: JSON files
- **Security**: Werkzeug security utilities
- **Export**: CSV, Excel (openpyxl)

## License

This project is open source and available under the MIT License.
