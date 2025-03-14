import sqlite3
from flask import Flask, render_template, url_for, flash, redirect, request
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

def get_db_connection():
    conn = sqlite3.connect('site.db')
    conn.row_factory = sqlite3.Row
    return conn

@login_manager.user_loader
def load_user(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        return User(user['id'], user['username'], user['email'], user['image_file'], user['password'])
    return None

class User(UserMixin):
    def __init__(self, id, username, email, image_file, password):
        self.id = id
        self.username = username
        self.email = email
        self.image_file = image_file
        self.password = password

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user WHERE username = ?', (username.data,)).fetchone()
        conn.close()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user WHERE email = ?', (email.data,)).fetchone()
        conn.close()
        if user:
            raise ValidationError('That email is already in use. Please choose a different one.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class StoryForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Create Story')

class ContributionForm(FlaskForm):
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Add to Story')

@app.route("/")
@app.route("/home")
@login_required
def home():
    conn = get_db_connection()
    stories = conn.execute('SELECT * FROM story').fetchall()
    conn.close()
    return render_template('home.html', stories=stories)

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        conn = get_db_connection()
        conn.execute('INSERT INTO user (username, email, password, image_file) VALUES (?, ?, ?, ?)',
                     (form.username.data, form.email.data, hashed_password, 'default.jpg'))
        conn.commit()
        conn.close()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM user WHERE email = ?', (form.email.data,)).fetchone()
        conn.close()
        if user and bcrypt.check_password_hash(user['password'], form.password.data):
            login_user(User(user['id'], user['username'], user['email'], user['image_file'], user['password']))
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/story/new", methods=['GET', 'POST'])
@login_required
def new_story():
    form = StoryForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        conn.execute('INSERT INTO story (title, content, user_id, date_posted) VALUES (?, ?, ?, ?)',
                     (form.title.data, form.content.data, current_user.id, datetime.utcnow()))
        conn.commit()
        conn.close()
        flash('Your story has been created!', 'success')
        return redirect(url_for('home'))
    return render_template('new_story.html', title='New Story', form=form)

@app.route("/story/<int:story_id>", methods=['GET', 'POST'])
@login_required
def add_story(story_id):
    conn = get_db_connection()
    story = conn.execute('SELECT * FROM story WHERE id = ?', (story_id,)).fetchone()
    conn.close()
    if not story:
        return redirect(url_for('home'))
    form = ContributionForm()
    if form.validate_on_submit():
        conn = get_db_connection()
        conn.execute('INSERT INTO contribution (content, user_id, story_id, date_posted) VALUES (?, ?, ?, ?)',
                     (form.content.data, current_user.id, story_id, datetime.utcnow()))
        conn.commit()
        conn.close()
        flash('Your contribution has been added!', 'success')
        return redirect(url_for('home'))
    return render_template('add_story.html', title='Add to Story', form=form, story=story)
