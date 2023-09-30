import jwt
from functools import wraps
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
from flask import session
import datetime


app = Flask(__name__)
app.secret_key = '12345'

# User model (replace with your database model)
class User(UserMixin):
    def __init__(self, id, age, role):
        self.id = id
        self.age = age
        self.role = role

# Replace with your user data
users = {
    'user1': {'password': 'pass123', 'age': 25, 'role': 'user'},
    'admin': {'password': 'admin123', 'age': 22, 'role': 'admin'},
    'user30': {'password': 'pass30', 'age': 32, 'role': 'user'},
}

# JWT secret key (replace with a strong secret key)
jwt_secret_key = '123232'

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    user_info = users.get(user_id)
    if user_info:
        return User(user_id, user_info['age'], user_info['role'])
    return None

# Custom decorator for role-based access control (RBAC)
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated and current_user.role == role:
                return f(*args, **kwargs)
            else:
                flash('Unauthorized. You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
        return decorated_function
    return decorator

# Custom decorator for attribute-based access control (ABAC)
def age_required(min_age):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated and current_user.age >= min_age:
                return f(*args, **kwargs)
            else:
                flash('Unauthorized. You do not have permission to access this page.', 'danger')
                return redirect(url_for('home'))
        return decorated_function
    return decorator

# Custom decorator for JWT-based authentication
def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is already authenticated via Flask-Login
        if current_user.is_authenticated:
            return f(*args, **kwargs)

        token = request.headers.get('Authorization')
        if token is None:
            flash('Unauthorized. Token missing.', 'danger')
            return jsonify({'message': 'Unauthorized. Token missing.'}), 401

        try:
            payload = jwt.decode(token, jwt_secret_key, algorithms=['HS256'])
            user_id = payload['sub']
        except jwt.ExpiredSignatureError:
            flash('Unauthorized. Token expired.', 'danger')
            return jsonify({'message': 'Unauthorized. Token expired.'}), 401
        except jwt.InvalidTokenError:
            flash('Unauthorized. Invalid token.', 'danger')
            return jsonify({'message': 'Unauthorized. Invalid token.'}), 401

        if user_id not in users:
            flash('Unauthorized. User not found.', 'danger')
            return jsonify({'message': 'Unauthorized. User not found.'}), 401

        user_info = users.get(user_id)
        user = User(user_id, user_info['age'], user_info['role'])
        login_user(user)
        return f(*args, **kwargs)
    return decorated_function

# Custom decorator for RBAC + Claims
def rbac_with_claims_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.headers.get('Authorization')
            if token is None:
                flash('Unauthorized. Token missing.', 'danger')
                return redirect(url_for('home'))

            try:
                payload = jwt.decode(token, jwt_secret_key, algorithms=['HS256'])
                user_id = payload['sub']
                user_role = payload.get('role')
            except jwt.ExpiredSignatureError:
                flash('Unauthorized. Token expired.', 'danger')
                return redirect(url_for('home'))
            except jwt.InvalidTokenError:
                flash('Unauthorized. Invalid token.', 'danger')
                return redirect(url_for('home'))

            if user_id not in users or user_role != role:
                flash('Unauthorized. Access denied.', 'danger')
                return redirect(url_for('home'))

            user_info = users.get(user_id)
            user = User(user_id, user_info['age'], user_info['role'])
            login_user(user)
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Define a WTForms login form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')

@app.route('/')
def home():
 current_year = datetime.datetime.now().year
 return render_template('homepage.html', current_year=current_year)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Example login logic (replace with your actual logic)
        if username in users and users[username]['password'] == password:
            user_info = users[username]
            user = User(username, user_info['age'], user_info['role'])
            login_user(user)
            flash('Login successful', 'success')

            if user_info['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))  # Redirect admin to admin_dashboard
            else:
                return redirect(url_for('user_dashboard'))   # Redirect user to user_dashboard

        else:
            flash('Login failed. Invalid username or password.', 'danger')

    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out', 'success')
    return redirect(url_for('home'))

@app.route('/user_profile')
@login_required
@age_required(30)  # Restrict access to users who are at least 30 years old
def user_profile():
    print(f"Debug: User age: {current_user.age}")
    return render_template('user_profile.html')

@app.route('/user_dashboard')
@login_required
@role_required('user')
def user_dashboard():
    return render_template('user_dashboard.html')

@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Protected resource route
@app.route('/protected_resource')
@login_required
def protected_resource():
    if current_user.role == 'admin':
        # Admins can access the protected resource
        return render_template('protected_resource.html', current_user_id=current_user.id, user_age=current_user.age, user_role=current_user.role)
    elif current_user.age >= 30:
        # Users with age greater than or equal to 30 can access the protected resource
        return render_template('protected_resource.html', current_user_id=current_user.id, user_age=current_user.age, user_role=current_user.role)
    else:
        flash('Unauthorized. Access denied.', 'danger')
        return redirect(url_for('home'))  # Flash the message and redirect to the home page



if __name__ == '__main__':
    app.run(debug=True)
