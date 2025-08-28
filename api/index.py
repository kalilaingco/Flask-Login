import os
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, redirect, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__, template_folder='templates')

# Configure Flask for Vercel's read-only filesystem
if os.environ.get('VERCEL'):
    app.instance_path = '/tmp'

# Database configuration - PostgreSQL only
database_url = os.environ.get('DATABASE_URL')
if not database_url:
    raise ValueError("DATABASE_URL environment variable is required")

# Convert postgres:// to postgresql:// for SQLAlchemy compatibility
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configure connection pooling for serverless
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'pool_timeout': 20,
    'max_overflow': 0
}

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    login_count = db.Column(db.Integer, default=1)

    def __repr__(self):
        return f'<User {self.email}>'

class RegisterForm(FlaskForm):
    first_name = StringField('First Name', validators=[
        InputRequired(message="First name is required"),
        Length(min=1, max=50, message="First name must be between 1-50 characters")
    ], render_kw={"placeholder": "First Name"})
    
    last_name = StringField('Last Name', validators=[
        InputRequired(message="Last name is required"),
        Length(min=1, max=50, message="Last name must be between 1-50 characters")
    ], render_kw={"placeholder": "Last Name"})
    
    email = EmailField('Work Email', validators=[
        InputRequired(message="Email is required"),
        Email(message="Invalid email format")
    ], render_kw={"placeholder": "yourname@getcovered.io"})
    
    password = PasswordField('Password', validators=[
        InputRequired(message="Password is required")
    ], render_kw={"placeholder": "Password"})
    
    confirm_password = PasswordField('Confirm Password', validators=[
        InputRequired(message="Please confirm your password")
    ], render_kw={"placeholder": "Confirm Password"})
    
    submit = SubmitField("Create Account")
    
    def validate_email(self, email):
        if not email.data.endswith('@getcovered.io'):
            raise ValidationError('Email must be a @getcovered.io address')
        
        existing_user = User.query.filter_by(email=email.data.lower()).first()
        if existing_user:
            raise ValidationError('An account with this email already exists')
    
    def validate_password(self, password):
        pwd = password.data
        
        if len(pwd) < 12:
            raise ValidationError('Password must be at least 12 characters long')
        
        has_upper = any(c.isupper() for c in pwd)
        has_lower = any(c.islower() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        has_symbol = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in pwd)
        
        if not has_upper:
            raise ValidationError('Password must contain at least one uppercase letter')
        if not has_lower:
            raise ValidationError('Password must contain at least one lowercase letter')
        if not has_digit:
            raise ValidationError('Password must contain at least one number')
        if not has_symbol:
            raise ValidationError('Password must contain at least one symbol')
        
        for i in range(len(pwd) - 2):
            if pwd[i] == pwd[i+1] == pwd[i+2]:
                raise ValidationError('Password cannot contain 3 or more repeated characters in a row')
        
        if hasattr(self, 'email') and self.email.data:
            email_local = self.email.data.split('@')[0].lower()
            pwd_lower = pwd.lower()
            
            different_chars = 0
            min_len = min(len(email_local), len(pwd_lower))
            
            for i in range(min_len):
                if email_local[i] != pwd_lower[i]:
                    different_chars += 1
            
            different_chars += abs(len(email_local) - len(pwd_lower))
            
            if different_chars < 5:
                raise ValidationError('Password must differ from email username by at least 5 characters')
    
    def validate_confirm_password(self, confirm_password):
        if self.password.data != confirm_password.data:
            raise ValidationError('Passwords do not match')

class LoginForm(FlaskForm):
    username = EmailField('Email', validators=[
        InputRequired(message="Email is required"),
        Email(message="Invalid email format")
    ], render_kw={"placeholder": "Enter your email"})
    
    password = PasswordField('Password', validators=[
        InputRequired(message="Password is required"),
        Length(min=12, max=255, message="Password must be at least 12 characters")
    ], render_kw={"placeholder": "Enter your password"})
    
    submit = SubmitField("Sign In")

# Routes
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/api/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.username.data.lower().strip()).first()
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            user.login_count = (user.login_count or 0) + 1
            db.session.commit()
            
            login_user(user)
            flash(f'Welcome back, {user.first_name}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password. Please try again.', 'error')
    
    return render_template('login.html', form=form)

@app.route('/api/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            new_user = User(
                first_name=form.first_name.data.strip(),
                last_name=form.last_name.data.strip(),
                email=form.email.data.lower().strip(),
                password=hashed_password,
                login_count=0
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash(f'Account created successfully for {form.first_name.data}! Please sign in.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            flash('An error occurred while creating your account. Please try again.', 'error')
            app.logger.error(f'Registration error: {str(e)}')
    
    return render_template('register.html', form=form)

@app.route('/api/dashboard')
@login_required
def dashboard():
    if current_user.created_at:
        days_since_registration = (datetime.utcnow() - current_user.created_at).days
    else:
        days_since_registration = 0
    
    return render_template('dashboard.html', 
                         days_since_registration=days_since_registration,
                         login_count=current_user.login_count or 1,
                         tasks_completed=0)

@app.route('/api/settings')
@app.route('/api/profile')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/api/logout')
@login_required
def logout():
    flash(f'Goodbye, {current_user.first_name}! You have been logged out successfully.', 'info')
    logout_user()
    return redirect(url_for('home'))

@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    return jsonify({
        'first_name': current_user.first_name,
        'last_name': current_user.last_name,
        'email': current_user.email,
        'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
        'login_count': current_user.login_count or 1
    })

@app.route('/api/profile', methods=['PUT'])
@login_required
def update_profile():
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        
        if not first_name or not last_name:
            return jsonify({'message': 'First name and last name are required'}), 400
        
        if len(first_name) > 50 or len(last_name) > 50:
            return jsonify({'message': 'Names must be 50 characters or less'}), 400
        
        current_user.first_name = first_name
        current_user.last_name = last_name
        
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'first_name': current_user.first_name,
            'last_name': current_user.last_name
        })
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Profile update error: {str(e)}')
        return jsonify({'message': 'Failed to update profile'}), 500

# Database initialization route (temporary - remove after first deployment)
@app.route('/init-db')
def init_db():
    try:
        with app.app_context():
            db.create_all()
        return "Database initialized successfully"
    except Exception as e:
        return f"Error initializing database: {str(e)}"

# Health check route
@app.route('/health')
def health():
    return {'status': 'ok', 'message': 'App is running'}

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

@app.context_processor
def inject_user():
    return dict(current_user=current_user)

@app.template_filter('days_ago')
def days_ago_filter(date):
    if not date:
        return 'Unknown'
    delta = datetime.utcnow() - date
    if delta.days == 0:
        return 'Today'
    elif delta.days == 1:
        return 'Yesterday'
    else:
        return f'{delta.days} days ago'

# Export app for Vercel
app = app

# For local development only
if __name__ == '__main__':
    app.run(debug=True)