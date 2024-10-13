import os
from datetime import datetime
from flask_babel import Babel
from flask import Flask, render_template, request, redirect, flash, url_for
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploadedfiles')
babel = Babel(app)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)

# Define models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    name = db.Column(db.String(1000))
    email = db.Column(db.String(100), nullable=False)
    country = db.Column(db.String(100))
    subscription = db.Column(db.String(100))
    credit = db.Column(db.Integer, default=0)
    role = db.Column(db.String(100), default="user")
    pay = db.Column(db.Boolean(), default=False)
    message = db.Column(db.String(1000))
    starting_day = db.Column(db.DateTime)
    due_date = db.Column(db.DateTime)
    delegate = db.Column(db.DateTime)
    photo_filename = db.Column(db.String(1000))

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(1000), unique=True, nullable=False)
    math = db.Column(db.Integer, default=0)
    arabic = db.Column(db.Integer, default=0)
    english = db.Column(db.Integer, default=0)
    science = db.Column(db.Integer, default=0)
    social_studies = db.Column(db.Integer, default=0)
    total = db.Column(db.Integer, default=0)
    grades = db.Column(db.String(1000))
    faculty = db.Column(db.String(1000))

class Complaint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    subject = db.Column(db.String(100))
    mark = db.Column(db.Integer)
    complaint_text = db.Column(db.String(1000))
    date_submitted = db.Column(db.DateTime, default=datetime.utcnow)
    resolved = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref='complaints')

# Load user function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize Flask-Admin
admin = Admin(app)
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(Student, db.session))
admin.add_view(ModelView(Complaint, db.session))

# Define routes
@app.route("/")
def start():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        phone = request.form['phone']
        name = request.form['name']
        hashed_password = generate_password_hash(request.form.get('password'), method='pbkdf2:sha256', salt_length=8)
        new_user = User(phone=phone, password=hashed_password, name=name, role="student")
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        phone = request.form['phone']
        password = request.form['password']
        user = User.query.filter_by(phone=phone).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your phone number and/or password.', 'danger')
    return render_template('login.html')

@app.route('/dash')
@login_required
def dashboard():
    if current_user.role == "teacher":
        complaints = Complaint.query.filter_by(resolved = True).all()
        return render_template("dash.html", complaints = complaints)
    elif current_user.role == "student":
        student = Student.query.filter_by(phone = current_user.phone).first()
        return render_template("student_dash.html", student=student)
    elif current_user.role == "admin":
        complaints = Complaint.query.all()
        return render_template("admin_dashboard.html", complaints=complaints)
    else:
        return "Unauthorized Access", 403

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
def admin_dashboard():
    if not current_user.role == "admin":
        flash('Unauthorized access', 'danger')
        return redirect(url_for('start'))

    complaints = Complaint.query.all()
    users = User.query.all()
    students = Student.query.all()

    if request.method == 'POST':
        action = request.form.get('action')
        complaint_id = request.form.get('complaint_id')
        complaint = Complaint.query.get(complaint_id)
        if complaint:
            if action == 'approve':
                complaint.resolved = True
                db.session.commit()
                flash('Complaint approved and sent to teacher.', 'success')
            elif action == 'delete':
                db.session.delete(complaint)
                db.session.commit()
                flash('Complaint deleted.', 'success')
            else:
                flash('Invalid action.', 'danger')
        else:
            flash('Complaint not found.', 'danger')
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_dashboard.html', users=users, students=students, complaints=complaints)

@app.route('/add_student', methods=['GET', 'POST'])
def add_student():
    if request.method == 'POST':
        phone = request.form['phone']
        math = int(request.form['math'])
        arabic = int(request.form['arabic'])
        english = int(request.form['english'])
        science = int(request.form['science'])
        social_studies = int(request.form['social_studies'])
        total = math + arabic + english + science + social_studies

        # Determine grade based on the total marks
        if 450 <= total <= 500:
            grade = 'A+'
        elif 400 <= total < 450:
            grade = 'A'
        else:
            grade = 'A-'

        existing_student = Student.query.filter_by(phone=phone).first()
        if existing_student:
            existing_student.math = math
            existing_student.arabic = arabic
            existing_student.english = english
            existing_student.science = science
            existing_student.social_studies = social_studies
            existing_student.total = total
            existing_student.grades = grade
            db.session.commit()
        else:
            new_student = Student(
                phone=phone,
                math=math,
                arabic=arabic,
                english=english,
                science=science,
                social_studies=social_studies,
                total=total,
                grades=grade
            )
            db.session.add(new_student)
            db.session.commit()
            hashed_password = generate_password_hash(phone, method='pbkdf2:sha256', salt_length=8)
            new_user = User(phone=phone, password=hashed_password, name='Student', role="student")
            db.session.add(new_user)
            db.session.commit()
        return redirect(url_for('dashboard'))
    return render_template('student_form.html')


@app.route('/complain', methods=['GET', 'POST'])
@login_required
def complain():
    if current_user.role != "student":
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('start'))
    if request.method == 'POST':
        subject = request.form.get('subject')
        mark = request.form.get('mark')
        complaint_text = request.form.get('complaint')
        new_complaint = Complaint(subject=subject, mark=mark, complaint_text=complaint_text, user_id=current_user.id)
        db.session.add(new_complaint)
        db.session.commit()
        flash('Your complaint has been submitted.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('complain.html')

@app.route('/approve_complaint/<int:complaint_id>', methods=['POST'])
@login_required
def approve_complaint(complaint_id):
    if not current_user.role == "admin":
        flash('Unauthorized access', 'danger')
        return redirect(url_for('start'))

    complaint = Complaint.query.get(complaint_id)
    if complaint:
        complaint.resolved = True
        db.session.commit()
        flash('Complaint approved.', 'success')
    else:
        flash('Complaint not found.', 'danger')
    return redirect(url_for('admin_dashboard'))


@app.route('/delete_complaint/<int:complaint_id>', methods=['POST'])
@login_required
def delete_complaint(complaint_id):
    if not current_user.role == "admin":
        flash('Unauthorized access', 'danger')
        return redirect(url_for('start'))

    complaint = Complaint.query.get(complaint_id)
    if complaint:
        db.session.delete(complaint)
        db.session.commit()
        flash('Complaint deleted.', 'success')
    else:
        flash('Complaint not found.', 'danger')
    return redirect(url_for('admin_dashboard'))


@app.route('/edit_complaint', methods=['POST'])
@login_required
def edit_complaint():
    if current_user.role != "teacher":
        flash('Unauthorized access', 'danger')
        return redirect(url_for('start'))

    complaint_id = request.form.get('complaint_id')
    new_mark = request.form.get('new_mark')

    complaint = Complaint.query.get(complaint_id)
    if complaint:
        complaint.mark = new_mark
        db.session.commit()
        flash('Complaint mark updated successfully.', 'success')

        # Notify student (You can use email or messaging system)
        student = User.query.get(complaint.user_id)
        student.message = f'Your complaint about {complaint.subject} has been updated. New mark: {new_mark}'
        db.session.commit()
    else:
        flash('Complaint not found.', 'danger')

    return redirect(url_for('dashboard'))



@app.route('/reject_complaint/<int:complaint_id>', methods=['POST'])
@login_required
def reject_complaint(complaint_id):
    if current_user.role != "teacher":
        flash('Unauthorized access', 'danger')
        return redirect(url_for('start'))

    complaint = Complaint.query.get(complaint_id)
    if complaint:
        db.session.delete(complaint)
        db.session.commit()
        flash('Complaint rejected and deleted.', 'success')

        # Notify student (You can use email or messaging system)
        student = User.query.get(complaint.user_id)
        student.message = f'Your complaint about {complaint.subject} has been rejected.'
        db.session.commit()
    else:
        flash('Complaint not found.', 'danger')

    return redirect(url_for('dashboard'))



if __name__ == "__main__":
    app.run(debug=True)
