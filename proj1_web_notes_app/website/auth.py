from flask import Blueprint, render_template, request, flash, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

#security through hashing
auth = Blueprint('auth', __name__)

@auth.route('/login', methods = ['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        #if user account exists
        if user: 
            if check_password_hash(user.password, password):
                flash('logged in successfully.', category="success")
                #saves user login information for them in the broswer
                login_user(user, remember = True)
                return redirect(url_for('views.home'))
            else:
                flash('password is incorrect.', category='error')
    return render_template("login.html", text="sup", bool = True, user = current_user)
 
@auth.route('/logout')
def logout():
    #function handled by flask-login package
    logout_user()
    #after logout bring to login page
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods = ['GET', 'POST'])
def sign_up():
    if request.method=='POST':
        email = request.form.get('email')
        firstName = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email = email).first()
        if user:
            flash('Email already exists', category='error')
        elif len(email) < 4:
            flash("email must be greater than 4 characters", category = "error")
        elif len(firstName) < 2:
            flash("First name must be greater than 1 character", category = "error")
        elif password1 != password2:
            flash("passwords do not match", category = "error")
        elif len(password1) < 7:
            flash("passwords must be at least 7 characters", category = "error")
        else:
            #add user to database
            new_user = User(email = email, first_name = firstName, password = generate_password_hash(password1, method = 'sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created!", category = "success")
            return redirect(url_for("views.home"))
    return render_template("sign_up.html", user = current_user)