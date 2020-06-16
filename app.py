from flask import Flask, render_template, session, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from flask_login import LoginManager, UserMixin, current_user, login_user, logout_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse

from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField
from wtforms.validators import DataRequired, ValidationError


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'not_so_super_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
login = LoginManager(app)

@login.user_loader
def load_user(id):
    return User.query.get(int(id))

login.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    
    def set_password(self, password):
        self.password = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password, password)
    
    def __repr__(self):
        return '<User {}>'.format(self.username)
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', backref=db.backref('posts', lazy=True))
    
    def __repr__(self):
        return '<Post {}>'.format(self.content)


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])    
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError("Username taken! Please choose another username.")
        
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError("An account has been registered under this email.")
    
    
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')
    remember_me = BooleanField('Remember Me')
    
class ChatForm(FlaskForm):
    chat = StringField('Chat', validators=[DataRequired()])
    submit = SubmitField('Submit')


@app.route('/', methods=['GET', 'POST'])
def index():
    title = 'Hello!'
    chatForm = ChatForm()
    posts = Post.query.all()
    if chatForm.validate_on_submit():
        chatText = chatForm.chat.data
        chatForm.chat.data = ''
        p = Post(content=chatText)
        
        if current_user.is_authenticated:
            current_user.posts.append(p)

        db.session.add(p)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('index.html', title=title, chatForm=chatForm, posts=posts)


@app.route('/clear_chat', methods=['GET', 'POST'])
def clearChat():
    posts = Post.query.all()
    for post in posts:
        db.session.delete(post)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password")
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        
        if not next_page or url_parse(next_page).netloc != ' ':
            return redirect(url_for('index'))
        return redirect(next_page)
    
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('You are now registered as {}'.format(form.username.data))
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

