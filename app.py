from flask import Flask, request, jsonify
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
from models import db, User, Task
from forms import RegistrationForm, LoginForm, TaskForm, TaskUpdateForm, PassChangeForm

app = Flask(__name__)
app.config.from_object('config.Config')

app.config['WTF_CSRF_ENABLED'] = False

migrate = Migrate(app, db)

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/register", methods=['POST'])
def register():
    if current_user.is_authenticated:
        return jsonify({"message": "Already logged in"}), 200

    data = request.form
    form = RegistrationForm(data)

    if form.validate():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Account created successfully"}), 201
    return jsonify({"errors": form.errors}), 400


@app.route("/changepass", methods=['POST'])
@login_required
def change_password():
    # Get current user
    user = current_user

    form = PassChangeForm(request.form)

    # Get the new password from the request data
    new_password = form.new_password.data
    # Get the old password from the request data
    old_password = form.old_password.data

    # Validate old and new passwords
    if not old_password or not new_password:
        return jsonify({"message": "Old and new passwords are required"}), 400

    # Check if the old password matches the current password
    if not bcrypt.check_password_hash(user.password, old_password):
        return jsonify({"message": "Old password is incorrect"}), 400

    # Hash the new password
    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    # Update user's password
    user.password = hashed_password
    db.session.commit()

    return jsonify({"message": "Password changed successfully"}), 200


@app.route("/login", methods=['POST'])
def login():
    if current_user.is_authenticated:
        return jsonify({"message": "Already logged in"}), 200

    data = request.form
    form = LoginForm(data)

    if form.validate():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            return jsonify({"message": "Login successful"}), 200
        else:
            return jsonify({"message": "Login unsuccessful. Please check username and password"}), 401
    return jsonify({"errors": form.errors}), 400


@app.route("/users", methods=['GET'])
@login_required
def get_users():
    users = User.query.all()
    user_list = []
    for user in users:
        user_data = {
            'id': user.id,
            'username': user.username,
        }
        user_list.append(user_data)
    return jsonify({'users': user_list})


@app.route("/user/<int:user_id>/tasks", methods=['GET'])
@login_required
def get_user_tasks(user_id):
    user = User.query.get_or_404(user_id)
    tasks = [{'id': task.id, 'name': task.name, 'type': task.type, 'description': task.description, 'status': task.status} for task in user.tasks]
    return jsonify({'tasks': tasks})


@app.route("/taskboard")
@login_required
def taskboard():
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    tasks_list = [{"id": task.id, "name": task.name, "type": task.type,
                   "description": task.description, "status": task.status
                   } for task in tasks]
    return jsonify({"tasks": tasks_list}), 200


@app.route("/logout")
def logout():
    logout_user()
    return jsonify({"message": "Logged out successfully"}), 200


@app.route("/task/add", methods=['POST'])
@login_required
def add_task():
    form = TaskForm(request.form)
    if form.validate():
        task = Task(name=form.name.data, type=form.type.data, description=form.description.data,
                    user_id=current_user.id, status=form.status.data)
        db.session.add(task)
        db.session.commit()
        return jsonify({"message": "Task added successfully"}), 201
    return jsonify({"errors": form.errors}), 400


@app.route("/task/<int:task_id>/edit", methods=['PUT'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return jsonify({"message": "Unauthorized! (different usserId)"}), 403

    form = TaskUpdateForm(request.form)
    if form.validate():
        # Update task attributes only if they are present in the request
        if form.name.data is not None:
            task.name = form.name.data
        if form.type.data is not None:
            task.type = form.type.data
        if form.description.data is not None:
            task.description = form.description.data
        if form.status.data is not None:
            task.status = form.status.data

        db.session.commit()
        return jsonify({"message": "Task updated successfully"}), 200
    return jsonify({"errors": form.errors}), 400


@app.route("/task/<int:task_id>/delete", methods=['DELETE'])
@login_required
def delete_task(task_id):
    task = Task.query.get_or_404(task_id)
    if task.user_id != current_user.id:
        return jsonify({"message": "Unauthorized! (different usserId)"}), 403

    db.session.delete(task)
    db.session.commit()
    return jsonify({"message": "Task deleted successfully"}), 200


if __name__ == '__main__':
    app.run(debug=True)
