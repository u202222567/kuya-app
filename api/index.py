import os
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
import datetime
from flask_migrate import Migrate

# --- App Initialization ---
load_dotenv()
app = Flask(__name__, template_folder='../templates', static_folder='../static')

# Create the temporary upload folder if it doesn't exist
if not os.path.exists('/tmp/uploads'):
    os.makedirs('/tmp/uploads')

# --- Configuration ---
app.config['SECRET_KEY'] = 'a-very-secret-and-hard-to-guess-key'
database_uri = os.getenv('DATABASE_URL')
if database_uri and database_uri.startswith("postgres://"):
    database_uri = database_uri.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_uri
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# --- Extensions ---
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    dni = db.Column(db.String(8), unique=True, nullable=False)
    password_hash = db.Column(db.String(60), nullable=False)
    reports = db.relationship('Report', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='commenter', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    problem_type = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    photo_filename = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comments = db.relationship('Comment', backref='report', lazy=True, cascade="all, delete-orphan")

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('report.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        user = User.query.filter_by(dni=request.form['dni']).first()
        if user and bcrypt.check_password_hash(user.password_hash, request.form['password']):
            login_user(user, remember=True)
            return redirect(url_for('home'))
        else:
            flash('Login failed. Please check DNI and password.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        if User.query.filter_by(dni=request.form['dni']).first():
            flash('DNI already registered. Please log in.', 'warning')
            return redirect(url_for('login'))
        hashed_password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(dni=request.form['dni'], password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Your account has been created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def home():
    reports = Report.query.order_by(Report.timestamp.desc()).all()
    return render_template('index.html', reports=reports)

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit_report():
    if request.method == 'POST':
        if 'photo' not in request.files or request.files['photo'].filename == '':
            flash('Photo is required.', 'danger')
            return redirect(request.url)
        file = request.files['photo']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_report = Report(
                problem_type=request.form['problem_type'],
                location=request.form['location'],
                description=request.form['description'],
                photo_filename=filename,
                author=current_user
            )
            db.session.add(new_report)
            db.session.commit()
            flash('Your report has been submitted!', 'success')
            return redirect(url_for('home'))
    return render_template('submit_report.html')

@app.route('/report/<int:report_id>', methods=['GET', 'POST'])
@login_required
def report_detail(report_id):
    report = Report.query.get_or_404(report_id)
    if request.method == 'POST':
        comment_text = request.form.get('comment_text')
        if comment_text:
            new_comment = Comment(text=comment_text, commenter=current_user, report=report)
            db.session.add(new_comment)
            db.session.commit()
            flash('Your comment has been added.', 'success')
            return redirect(url_for('report_detail', report_id=report.id))
    return render_template('report_detail.html', report=report)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Vercel needs a variable named 'app'
# This is our Flask application instance
# No need for __name__ == '__main__' block for Vercel