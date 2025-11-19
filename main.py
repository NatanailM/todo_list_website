from flask import Flask, render_template, request, flash, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = "ajdsfk5SAd1vapM4"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./instance/todolist.db"

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class SignupForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(500), nullable=False)
    tasks = db.relationship('Tasks', back_populates='user')


class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user = db.relationship("User", back_populates="tasks")
    task = db.Column(db.String(250), nullable=False)
    finished = db.Column(db.Boolean, nullable=False)


with app.app_context():
    db.create_all()


@app.route("/", methods=["GET", "POST"])
def home():
    tasks = Tasks.query.all()

    if request.method == "POST":
        task = request.form['task']

        return add_task(task=task)

    return render_template("index.html", tasks=tasks)


@app.route("/add_task")
def add_task(task):

    new_task = Tasks(
        user=current_user,
        task=task,
        finished=False
    )

    db.session.add(new_task)
    db.session.commit()

    return redirect(url_for('home'))


@app.route("/finish_task/<task_id>")
def finish_task(task_id):
    task = Tasks.query.filter_by(id=task_id).first()

    task.finished = 1

    db.session.commit()

    return redirect(url_for('home'))


@app.route("/unfinish_task/<task_id>")
def unfinish_task(task_id):
    task = Tasks.query.filter_by(id=task_id).first()

    task.finished = 0

    db.session.commit()

    return redirect(url_for('home'))


# @app.route("/delete_task/<task_id>")
# def delete_task(task_id):
#     task = Tasks.query.filter_by(id=task_id).first()
#
#     db.session.remove(task)
#     db.session.commit()
#
#     return redirect(url_for('home'))


@app.route("/signup", methods=['GET', 'POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():

        if User.query.filter_by(email=form.email.data).first():
            flash("You have already signed up with this email, log in instead.")
            return redirect(url_for('login'))

        hashed_password = generate_password_hash(
            password=form.password.data,
            method="pbkdf2:sha256",
            salt_length=8)

        new_user = User(
            email=form.email.data,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for('home'))

    return render_template("signup.html", form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()

        if not user:
            flash("Email doesn't exist. Please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Incorrect password. Please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('home'))

    return render_template("login.html", form=form)


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(debug=True)
