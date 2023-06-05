from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from wtforms.widgets import TextArea

#create login form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

#create a posts form
class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()], widget=TextArea())
    author = StringField("Author")
    submit = SubmitField("Submit")

#create a form class
class UserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password_hash = PasswordField("Password", validators=[DataRequired(), EqualTo('password_hash2', message='Passwords Must Match!')])
    password_hash2 = PasswordField("Confirm Password", validators=[DataRequired()])
    submit = SubmitField("Submit")

#Form class
class NamerForm(FlaskForm):
    name = StringField("What's your Name?", validators=[DataRequired()])
    submit = SubmitField("Submit")

#Form class
class PasswordForm(FlaskForm):
    email = StringField("What's your Email?", validators=[DataRequired()])
    password_hash = PasswordField("What's your Password?", validators=[DataRequired()])
    submit = SubmitField("Submit")