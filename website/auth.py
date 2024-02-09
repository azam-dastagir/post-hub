from flask import Blueprint,render_template, url_for,redirect, request, flash
from .models import User
from . import db
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

auth = Blueprint('auth', '__name__')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password,password):
                flash("Login Successful!", category="success")
                return redirect(url_for("views.home",user=current_user))
            else:
                flash("incorrect password! Please try again..",category="error")
        else:
            flash("Email doesnot exist.",category="error")
           
    return render_template("login.html",user=current_user)

@auth.route('/signup',methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        cnfm_password = request.form.get("cnfm_password")

        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()
        if email_exists:
            flash(message="User with that email already Exists",category="error")
        elif username_exists:
            flash(message="username has already taken!",category="error")
        elif (password !=cnfm_password):
            flash(message="passwords dont match",category="error")
        elif len(password) <6:
            flash(message="password must be 6 characters long!",category="error")
        else:
            new_user = User(email=email,username=username,password=generate_password_hash(password,method="sha256"))
            db.session.add(new_user)
            db.session.commit()
            login_user(user=new_user, remember= True)
            flash('Account Created!', category="success")
            return redirect(url_for('views.home',user=current_user))
    return render_template("signup.html",user=current_user)
    

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))