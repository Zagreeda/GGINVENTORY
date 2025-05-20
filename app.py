from flask import Flask, render_template, request, redirect, url_for, session, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    threshold = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(120))
    job_number = db.Column(db.String(120))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        if User.query.filter_by(username=username).first():
            return 'Username already exists'
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            return redirect(url_for('index'))
        return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    items = Item.query.all()
    return render_template('index.html', items=items)

@app.route('/add', methods=['POST'])
@login_required
def add():
    name = request.form['name']
    quantity = int(request.form['quantity'])
    threshold = int(request.form['threshold'])
    category = request.form['category']
    job_number = request.form['job_number']
    item = Item(name=name, quantity=quantity, threshold=threshold, category=category, job_number=job_number)
    db.session.add(item)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/adjust/<int:item_id>', methods=['POST'])
@login_required
def adjust(item_id):
    change = int(request.form['change'])
    item = Item.query.get(item_id)
    if item:
        item.quantity += change
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/delete/<int:item_id>', methods=['POST'])
@login_required
def delete(item_id):
    item = Item.query.get(item_id)
    if item:
        db.session.delete(item)
        db.session.commit()
    return redirect(url_for('index'))

@app.route('/export')
@login_required
def export():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Name', 'Quantity', 'Threshold', 'Category', 'Job Number'])
    for item in Item.query.all():
        writer.writerow([item.name, item.quantity, item.threshold, item.category, item.job_number])
    output.seek(0)
    return send_file(io.BytesIO(output.getvalue().encode()), mimetype='text/csv', as_attachment=True, download_name='inventory.csv')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

    
