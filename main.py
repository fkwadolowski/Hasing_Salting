from flask import Flask, render_template, request, url_for, redirect, flash, \
    send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, \
    current_user, logout_user
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'


# CREATE DATABASE


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Hasing and salting the password
        hash_and_salted_password = generate_password_hash(
            password=request.form[
                "password"], method='pbkdf2:sha256',
            salt_length=8)
        new_user = User(
            email=request.form['email'],
            name=request.form['name'],
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)
        return render_template("secrets.html", name=request.form["name"])

    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method=="POST":
        form_email=request.form['email']
        form_password=request.form['password']
        user = db.session.execute(db.select(User).filter(
            User.email == form_email)).scalar_one_or_none()

    return render_template("secrets.html")


@app.route('/secrets')
def secrets(name):
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    pass


@app.route('/download')
def download():
    return send_from_directory(directory='static/files',
                               path='cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
