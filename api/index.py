import os
from dotenv import load_dotenv
from flask import Flask, render_template, url_for, redirect, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wtforms import EmailField
from wtforms.validators import Email
from datetime import datetime
from urllib.parse import urlparse
import sqlite3



app = Flask(__name__, template_folder='templates')

load_dotenv()

if os.environ.get('VERCEL'):
    # Use /tmp which is writable on Vercel
    app.instance_path = '/tmp'
else:
    # Use default instance path for local development
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLITE_URL')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Database configuration
database_url = os.environ.get('DATABASE_URL')

if database_url:
    # Parse the database URL for cloud deployment
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
else:
    # Local development fallback
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Update template and static folder paths for Vercel
#template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'templates'))
#tatic_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'static'))

#app = Flask(__name__)

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
        # Check if email domain is @getcovered.io
        if not email.data.endswith('@getcovered.io'):
            raise ValidationError('Email must be a @getcovered.io address')
        
        # Check if email already exists
        existing_user = User.query.filter_by(email=email.data.lower()).first()
        if existing_user:
            raise ValidationError('An account with this email already exists')
    
    def validate_password(self, password):
        pwd = password.data
        
        # Length check
        if len(pwd) < 12:
            raise ValidationError('Password must be at least 12 characters long')
        
        # Character type checks
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
        
        # Check for repeated characters (3 or more in a row)
        for i in range(len(pwd) - 2):
            if pwd[i] == pwd[i+1] == pwd[i+2]:
                raise ValidationError('Password cannot contain 3 or more repeated characters in a row')
        
        # Check difference from email local part
        if hasattr(self, 'email') and self.email.data:
            email_local = self.email.data.split('@')[0].lower()
            pwd_lower = pwd.lower()
            
            # Calculate character differences
            different_chars = 0
            min_len = min(len(email_local), len(pwd_lower))
            
            # Count different characters at same positions
            for i in range(min_len):
                if email_local[i] != pwd_lower[i]:
                    different_chars += 1
            
            # Add extra characters if lengths differ
            different_chars += abs(len(email_local) - len(pwd_lower))
            
            if different_chars < 5:
                raise ValidationError('Password must differ from email username by at least 5 characters')
    
    def validate_confirm_password(self, confirm_password):
        if self.password.data != confirm_password.data:
            raise ValidationError('Passwords do not match')

# Updated LoginForm to use email instead of username
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
        # Look up user by email (form field is named 'username' but contains email)
        user = User.query.filter_by(email=form.username.data.lower().strip()).first()
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            # Update login count
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
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            
            # Create new user
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
    # Calculate days since registration
    if current_user.created_at:
        days_since_registration = (datetime.utcnow() - current_user.created_at).days
    else:
        days_since_registration = 0
    
    return render_template('dashboard.html', 
                         days_since_registration=days_since_registration,
                         login_count=current_user.login_count or 1,
                         tasks_completed=0)  # You can add task tracking later

@app.route('/api/settings')
@app.route('/api/profile')  # Alternative URL
@login_required
def settings():
    return render_template('settings.html')

@app.route('/api/logout')
@login_required
def logout():
    flash(f'Goodbye, {current_user.first_name}! You have been logged out successfully.', 'info')
    logout_user()
    return redirect(url_for('home'))

# API Routes for profile management
@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    """API endpoint to get current user profile data"""
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
    """API endpoint to update user profile"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'message': 'No data provided'}), 400
        
        # Validate required fields
        first_name = data.get('first_name', '').strip()
        last_name = data.get('last_name', '').strip()
        
        if not first_name or not last_name:
            return jsonify({'message': 'First name and last name are required'}), 400
        
        if len(first_name) > 50 or len(last_name) > 50:
            return jsonify({'message': 'Names must be 50 characters or less'}), 400
        
        # Update user data
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

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('500.html'), 500

# Context processor to make current_user available in all templates
@app.context_processor
def inject_user():
    return dict(current_user=current_user)

# Template filters
@app.template_filter('days_ago')
def days_ago_filter(date):
    """Calculate days ago from a datetime"""
    if not date:
        return 'Unknown'
    delta = datetime.utcnow() - date
    if delta.days == 0:
        return 'Today'
    elif delta.days == 1:
        return 'Yesterday'
    else:
        return f'{delta.days} days ago'

if __name__ == '__main__':
    if not os.environ.get('VERCEL'):
        with app.app_context():
            db.create_all()
            print("Database tables created successfully!")

        
        # Create 10 test users for development
with app.app_context():
    test_users_data = [
        {'first_name': 'John', 'last_name': 'Smith', 'email': 'john.smith@getcovered.io'},
        {'first_name': 'Sarah', 'last_name': 'Johnson', 'email': 'sarah.johnson@getcovered.io'},
        {'first_name': 'Michael', 'last_name': 'Brown', 'email': 'michael.brown@getcovered.io'},
        {'first_name': 'Emily', 'last_name': 'Davis', 'email': 'emily.davis@getcovered.io'},
        {'first_name': 'David', 'last_name': 'Wilson', 'email': 'david.wilson@getcovered.io'},
        {'first_name': 'Jessica', 'last_name': 'Miller', 'email': 'jessica.miller@getcovered.io'},
        {'first_name': 'Christopher', 'last_name': 'Garcia', 'email': 'christopher.garcia@getcovered.io'},
        {'first_name': 'Amanda', 'last_name': 'Martinez', 'email': 'amanda.martinez@getcovered.io'},
        {'first_name': 'Robert', 'last_name': 'Anderson', 'email': 'robert.anderson@getcovered.io'},
        {'first_name': 'Lisa', 'last_name': 'Taylor', 'email': 'lisa.taylor@getcovered.io'}
    ]

    users_created = 0
    users_skipped = 0

    for user_data in test_users_data:
        test_user = User.query.filter_by(email=user_data['email']).first()
        if not test_user:
            hashed_password = bcrypt.generate_password_hash('TestPassword123!').decode('utf-8')
            test_user = User(
                first_name=user_data['first_name'],
                last_name=user_data['last_name'],
                email=user_data['email'],
                password=hashed_password,
                login_count=0
            )
            db.session.add(test_user)
            users_created += 1
            print(f"Test user created: {user_data['email']} / TestPassword123!")
        else:
            users_skipped += 1
            print(f"Test user already exists: {user_data['email']}")

    if users_created > 0:
        db.session.commit()
        print(f"\nTest user creation complete! Created {users_created} users, skipped {users_skipped} existing users.")
    else:
        print(f"\nAll {len(test_users_data)} test users already exist.")

def migrate_sqlite_to_postgres():
    # Connect to SQLite
    sqlite_conn = sqlite3.connect('users.db')
    cursor = sqlite_conn.cursor()
    
    # Get data from SQLite
    cursor.execute("SELECT * FROM user")
    users = cursor.fetchall()
    
    # Insert into new database using SQLAlchemy
    # (Run this locally with your new DATABASE_URL)
    for user_data in users:
        # Create User objects and add to new database
        pass

app = app

app.run(debug=True)