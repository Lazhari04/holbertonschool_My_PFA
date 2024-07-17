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
class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    product_price = db.Column(db.Float, nullable=False)
    product_image = db.Column(db.String(200), nullable=False)


@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    product_name = request.form['product_name']
    product_price = request.form['product_price']
    product_image = request.form['product_image']
    cart_item = Cart(user_id=current_user.id, product_name=product_name, product_price=product_price, product_image=product_image)
    db.session.add(cart_item)
    db.session.commit()
    flash('Item added to cart!', 'success')
    return redirect('/cart')


@app.route('/cart')
@login_required
def cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    total_price = sum(item.product_price for item in cart_items)
    return render_template('cart.html', cart_items=cart_items, total_price=total_price, user=current_user)


@app.route('/remove_from_cart/<int:item_id>', methods=['POST'])
@login_required
def remove_from_cart(item_id):
    cart_item = Cart.query.get(item_id)
    if cart_item and cart_item.user_id == current_user.id:
        db.session.delete(cart_item)
        db.session.commit()
        flash('Item removed from cart!', 'success')
    return redirect('/cart')



@app.route('/process_payment', methods=['POST'])
@login_required
def process_payment():
    Cart.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('Payment successful! Your order is being processed.', 'success')
    return redirect('/')

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

    return render_template('login.html', user=current_user)

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

    return render_template('Register.html', user=current_user)

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

@app.route("/about")
def about():
    return render_template('about.html',user=current_user)


if __name__ == '__main__':
    app.run(debug=True)