from flask import Flask, redirect, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.db'
app.config['SECRET_KEY'] = 'azerty'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(200), unique=True, nullable=False)
    email = db.Column(db.String(200), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)




@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def create_tables():
    db.create_all()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if not user or not check_password_hash(user.password, password):
            flash('Login failed. Check your email and password.', 'error')
            return redirect('/login')

        login_user(user)
        flash('Logged in successfully!', 'success')
        return redirect('/')

    return render_template('login.html')

@app.route('/Register', methods=['GET', 'POST'])
def Register():
    if request.method == 'POST':
        print("Form Data:", request.form)  # Debugging statement
        if not request.form.get('username') or not request.form.get('email') or not request.form.get('password'):
            flash('Missing form fields', 'error')
            return redirect('/Register')

        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already Registed. Please log in.')
            return redirect('/login')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        flash('Registration successful!', 'success')
        return redirect('/')

    return render_template('Register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect('/login')

@app.route('/')
def home():
    return render_template('laz.html' ,user=current_user)

@app.route('/shop')
def shop():
    return render_template('shop.html',user=current_user)

@app.route('/contact')
def contact():
    return render_template('contact.html',user=current_user)

@app.route("/shop/WHEY")
def WHEY():
    return render_template('WHEY.html',user=current_user)

@app.route("/CREATINE")
def CREATINE():
    return render_template('CREATINE.html',user=current_user)

@app.route("/VITAMIN")
def VITAMIN():
    return render_template('VITAMIN.html',user=current_user)

if __name__ == '__main__':
    app.run(debug=True)