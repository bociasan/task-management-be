# from flask import Flask, render_template, url_for, flash, redirect
# from flask_sqlalchemy import SQLAlchemy
# from flask_bcrypt import Bcrypt
# from flask_login import LoginManager, login_user, current_user, logout_user, login_required
# from forms import RegistrationForm, LoginForm
# from models import db, User, Task
#
# app = Flask(__name__)
# app.config.from_object('config.Config')
# db.init_app(app)
# bcrypt = Bcrypt(app)
# login_manager = LoginManager(app)
# login_manager.login_view = 'login'
# login_manager.login_message_category = 'info'
#
#
# @login_manager.user_loader
# def load_user(user_id):
#     return User.query.get(int(user_id))
#
#
# @app.route("/register", methods=['GET', 'POST'])
# def register():
#     if current_user.is_authenticated:
#         return redirect(url_for('taskboard'))
#     form = RegistrationForm()
#     if form.validate_on_submit():
#         hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
#         user = User(username=form.username.data, password=hashed_password)
#         db.session.add(user)
#         db.session.commit()
#         flash('Your account has been created! You can now log in', 'success')
#         return redirect(url_for('login'))
#     return render_template('register.html', title='Register', form=form)
#
#
# @app.route("/login", methods=['GET', 'POST'])
# def login():
#     if current_user.is_authenticated:
#         return redirect(url_for('taskboard'))
#     form = LoginForm()
#     if form.validate_on_submit():
#         user = User.query.filter_by(username=form.username.data).first()
#         if user and bcrypt.check_password_hash(user.password, form.password.data):
#             login_user(user, remember=True)
#             return redirect(url_for('taskboard'))
#         else:
#             flash('Login Unsuccessful. Please check username and password', 'danger')
#     return render_template('login.html', title='Login', form=form)
#
#
# @app.route("/taskboard")
# @login_required
# def taskboard():
#     tasks = Task.query.filter_by(user_id=current_user.id).all()
#     return render_template('taskboard.html', tasks=tasks)
#
#
# @app.route("/logout")
# def logout():
#     logout_user()
#     return redirect(url_for('login'))
#
#
# if __name__ == '__main__':
#     app.run(debug=True)
