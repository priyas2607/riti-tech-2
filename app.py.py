from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Login activity model
class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    login_time = db.Column(db.DateTime, default=datetime.utcnow)
    logout_time = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", backref=db.backref("activities", lazy=True))

# Home route
@app.route('/')
def home():
    return render_template("home.html", user=session.get("user"))

# Signup route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("⚠️ Username already exists! Try another.", "error")
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash("✅ Signup successful! Please login.", "success")
        return redirect(url_for('login'))

    return render_template("signup.html")

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user'] = user.username

            # Record login activity
            activity = LoginActivity(user_id=user.id)
            db.session.add(activity)
            db.session.commit()

            flash("✅ You have successfully logged in!", "success")
            return redirect(url_for('home'))
        else:
            flash("❌ Invalid credentials. Try again.", "error")
            return redirect(url_for('login'))

    return render_template("login.html")

# Logout route
@app.route('/logout')
def logout():
    if "user" in session:
        user = User.query.filter_by(username=session['user']).first()
        if user:
            # Update last login record with logout time
            activity = LoginActivity.query.filter_by(
                user_id=user.id, logout_time=None
            ).order_by(LoginActivity.login_time.desc()).first()
            if activity:
                activity.logout_time = datetime.utcnow()
                db.session.commit()

        session.pop('user', None)
        flash("👋 You have successfully logged out.", "info")
    return redirect(url_for('home'))

# ✅ New route to view all registered users
@app.route('/users')
def users():
    all_users = User.query.all()
    return render_template("users.html", users=all_users)

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)