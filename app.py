from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import urllib.parse
import uuid

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with your own secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Initialize LoginManager
login_manager = LoginManager(app)
login_manager.login_view = 'login'  # The view to redirect to when login is required

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Define the User model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Define the Game model
class Game(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))

    def __repr__(self):
        return f"Game('{self.name}', '{self.description}')"

# Define the Registration model
class Registration(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    game_id = db.Column(db.Integer, db.ForeignKey('game.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('registrations', lazy=True, passive_deletes=True))
    game = db.relationship('Game', backref=db.backref('registrations', lazy=True))

    def __repr__(self):
        return f"Registration(UserID: '{self.user_id}', GameID: '{self.game_id}')"

# Define the Wallet model
class Wallet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    balance = db.Column(db.Float, default=0.0)
    transactions = db.relationship('Transaction', backref='wallet', lazy=True)

    def add_funds(self, amount):
        self.balance += amount
        db.session.add(self)
        db.session.commit()
        transaction = Transaction(wallet_id=self.id, amount=amount, transaction_type='add')
        db.session.add(transaction)
        db.session.commit()

# Define the Transaction model
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    wallet_id = db.Column(db.Integer, db.ForeignKey('wallet.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    transaction_type = db.Column(db.String(50), nullable=False)  # e.g., 'add', 'withdraw', 'win'
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

# Home route
@app.route('/')
def index():
    return render_template('index.html')

# Registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        if not username or not email or not password:
            flash('Please fill in all fields.', 'danger')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists!', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash('Please fill in both username and password.', 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

# User Dashboard Route
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    user_id = current_user.id
    user = User.query.get(user_id)
    registrations = Registration.query.filter_by(user_id=user_id).all()
    wallet = Wallet.query.filter_by(user_id=user_id).first()

    if request.method == 'POST':
        upi_id = request.form.get('upi_id')
        amount = float(request.form.get('amount'))
        if amount <= 0:
            flash('Amount must be greater than zero.', 'danger')
            return redirect(url_for('dashboard'))
         # Generate unique transaction and reference IDs
        transaction_id = str(uuid.uuid4())
        reference_id = str(uuid.uuid4())
        
        

        upi_url = (
            f'upi://pay?pa=8006199683@ybl&pn=admin&am=1.00&cu=INR'

        )
        

        # Add funds to wallet (simulate payment success)
        if wallet:
            wallet.add_funds(amount)
            flash('Funds added successfully!', 'success')
        else:
            flash('Wallet not found.', 'danger')
        print(upi_url)
        return redirect(upi_url)
    

    return render_template('dashboard.html', user=user, registrations=registrations, wallet=wallet)

# Logout route
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# Games list route
@app.route('/games')
def games():
    games = Game.query.all()
    return render_template('games.html', games=games)

# Register for a game
@app.route('/register_game/<int:game_id>', methods=['POST'])
@login_required
def register_game(game_id):
    user_id = current_user.id  # Use current_user from Flask-Login

    game = Game.query.get(game_id)
    if not game:
        flash('Game not found!', 'danger')
        return redirect(url_for('games'))

    registration = Registration(user_id=user_id, game_id=game_id)
    db.session.add(registration)
    db.session.commit()

    flash('Successfully registered for the game!', 'success')
    return redirect(url_for('games'))

# Admin Dashboard Route
@app.route('/admin')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    users = User.query.all()
    games = Game.query.all()
    registrations = Registration.query.all()
    return render_template('admin/dashboard.html', users=users, games=games, registrations=registrations)

# Admin Login Route
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username == 'admin' and password == 'password':  # Replace with real credentials
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('admin/login.html')

# Admin Logout Route
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

# Admin Delete User Route
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('admin_logged_in'):
        flash('You must be logged in as an admin to perform this action.', 'danger')
        return redirect(url_for('admin_login'))

    user = User.query.get(user_id)
    if not user:
        flash('User not found!', 'danger')
        return redirect(url_for('admin_dashboard'))

    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')

    return redirect(url_for('admin_dashboard'))

# Require Admin Login for Admin Routes
@app.before_request
def require_admin_login():
    if request.endpoint and request.endpoint.startswith('admin') and not session.get('admin_logged_in'):
        if request.endpoint != 'admin_login':
            return redirect(url_for('admin_login'))

# Create database and tables if they don't exist
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)



