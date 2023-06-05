from flask import Flask, render_template, flash, request, redirect, url_for
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import date
from wtforms.widgets import TextArea
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user



#Flask instance

app = Flask(__name__)
#add database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
#secret key
app.config['SECRET_KEY'] = "KLASSICLE"

#intialize database

db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.app_context().push()

#Flask_Login things
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

#create login form
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Submit")


#Create Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            #check hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash("Logged In Successfully.")
                return redirect(url_for('dashboard'))
            else:
                flash("Incorrect Password, Try again.")
        else:
            flash("User Credentials Do Not Exist, Try Again.")

    return render_template('login.html', form=form)

#Logout
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('Logged Out Successfully.')
    return redirect(url_for('login'))


#Create Dashbooard Page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    form = UserForm()
    id = current_user.id
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("dashboard.html", form=form, name_to_update=name_to_update)
        except:
            db.session.commit()
            flash("User Failed to Update!")
            return render_template("dashboard.html", form=form, name_to_update=name_to_update)
    else:
        return render_template("dashboard.html", form=form, name_to_update=name_to_update, id=id)

    return render_template('dashboard.html')




# post model
class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

class PostForm(FlaskForm):
    title = StringField("Title", validators=[DataRequired()])
    content = StringField("Content", validators=[DataRequired()], widget=TextArea())
    author = StringField("Author", validators=[DataRequired()])
    submit = SubmitField("Submit")

@app.route('/posts')
def posts():
    #grab posts from db
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template("posts.html", posts=posts)

#individual post page 
@app.route('/posts/<int:id>')
def post(id):
    post = Posts.query.get_or_404(id)
    return render_template('post.html', post=post)

#delete posts 
@app.route('/posts/delete/<int:id>')
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    try:
        #updating the db
        db.session.delete(post_to_delete)
        db.session.commit()

        #message
        flash("Post Deleted Successfully!")

        #grab all posts in db
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts=posts)
    
    except:
        #Error message
        flash("Error, Post was not deleted!")

        #grab all posts in db
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html", posts=posts)





#edit post page
@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.content = form.content.data

        #update db
        db.session.add(post)
        db.session.commit()
        flash("Post Updated Successfully!")
        return redirect(url_for('post', id=post.id))
    form.title.data = post.title 
    form.author.data = post.author
    form.content.data = post.content
    return render_template('edit_post.html', form=form)


#add post page
@app.route('/add-post', methods = ['GET', 'POST'])
def add_post():
    form = PostForm()

    if form.validate_on_submit():
        post = Posts(title=form.title.data, content=form.content.data, author=form.author.data)
        # clear form
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''

        #add post data to db
        db.session.add(post)
        db.session.commit()

        #success message
        flash("Post Submitted Successfully!")

        #redirect to the webpage
    return render_template("add_post.html", form=form)

#JSON
@app.route('/date')
def get_current_date():
    favorite_pizza = {
        ""
    }
    return {"Date": date.today()}

#create model
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(200), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    #password code
    password_hash = db.Column(db.String(128))

    @property
    def password(self):
        raise AttributeError('Password is not a readable attribute!')
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)
         
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    


    # create a string
    def __repr__(self):
        return '<Name %r>' % self.name

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

@app.route('/')

#def index():
#   return "<h1>Hello world!</h1>"

def index():
   first_name = "Dilhan"

   favorite_pizza = ["pepperoni", "Cheese", "Mushrooms", 41]
   return render_template("index.html", first_name=first_name, favorite_pizza=favorite_pizza)


#localhost:5000/user/Dilhan
@app.route('/user/<name>')

def user(name):
   return render_template("user.html", user_name=name)

#Invalid URL
#Error Handling Code
@app.errorhandler(400)
def bad_request(e):
    return render_template('400.html'), 400

@app.errorhandler(401)
def unauthorized(e):
    return render_template('401.html'), 401

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(413)
def content_too_large(e):
    return render_template('413.html'), 413

@app.errorhandler(415)
def unsupported_media(e):
    return render_template('415.html'), 415

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Create pw test page
@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
   email = None
   password = None
   pw_to_check = None
   passed = None
   form = PasswordForm()

   # validate form
   if form.validate_on_submit():
       email = form.email.data
       password = form.password_hash.data
       form.email.data = ''
       form.password_hash.data = ''
       #look up user by email address
       pw_to_check = Users.query.filter_by(email=email).first()

       #check hashed pw
       passed = check_password_hash(pw_to_check.password_hash, password)


   return render_template("test_pw.html", email = email, password = password, 
                                          pw_to_check = pw_to_check, 
                                          passed = passed, 
                                          form = form)


# Create name page
@app.route('/name', methods=['GET', 'POST'])
def name():
   name = None
   form = NamerForm()
   # validate form
   if form.validate_on_submit():
       name = form.name.data
       form.name.data = ''
   return render_template("name.html", name = name, form = form)

#add user
@app.route('/user/add', methods = ['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()
    
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            #hash password
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(name=form.name.data, email=form.email.data, password_hash=hashed_pw)
            #csuf student validation
            if '@csu.fullerton.edu' not in user.email:
                flash("You are not a CSUF Student!")
                return render_template("add_user.html", form=form, name=name)
        
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.email.data = ''
        form.password_hash = ''
        flash("User Added Successfully!")
    our_users = Users.query.order_by(Users.date_added)

    return render_template("add_user.html", form=form, name=name, our_users=our_users)

#update user info
@app.route('/update/<int:id>', methods = ['GET', 'POST'])
def update(id):
    form = UserForm()
    name_to_update = Users.query.get_or_404(id)
    if request.method == "POST":
        name_to_update.name = request.form['name']
        name_to_update.email = request.form['email']
        try:
            db.session.commit()
            flash("User Updated Successfully!")
            return render_template("update.html", form=form, name_to_update=name_to_update)
        except:
            db.session.commit()
            flash("User Failed to Update!")
            return render_template("update.html", form=form, name_to_update=name_to_update)
    else:
        return render_template("update.html", form=form, name_to_update=name_to_update, id=id)

@app.route('/delete/<int:id>')
def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()

    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash("User Deleted Successfully!")
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html", form=form, name=name, our_users=our_users)
    
    except:
        flash("User was not deleted!")
        return render_template("add_user.html", form=form, name=name, our_users=our_users)
    
