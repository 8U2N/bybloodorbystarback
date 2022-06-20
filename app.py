from flask import Flask, request, jsonify, session
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
import os
from flask_bcrypt import Bcrypt

app = Flask(__name__)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)
ma = Marshmallow(app)
CORS(app)

basedir = os.path.abspath(os.path.dirname(__file__))
app.config['JWT_SECRET_KEY'] = 'd7ed3faa31b8e1cd4a19493071cbaa40ef58'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'app.sqlite')


# _____________
# |  Schemas  |
# V           V

class Admin(db.Model):
    
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    email = db.Column(db.String(255), unique=False, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=True)


    def __init__(self, email, password):
        self.email = email
        self.password = password


class AdminSchema(ma.Schema):
    class Meta:
        fields = ('id', 'email', 'password')


admin_schema = AdminSchema()
multi_admin_schema = AdminSchema(many=True)

class User(db.Model):
    
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    
    first_name = db.Column(db.String(255), unique=False, nullable=False)
    last_name = db.Column(db.String(255), unique=False, nullable=False)
    email = db.Column(db.String(255), unique=False, nullable=False)
    favorite = db.Column(db.Text, unique=False, nullable=True)


    def __init__(self, first_name, last_name, email, favorite):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.favorite = favorite


class UserSchema(ma.Schema):
    class Meta:
        fields = ('id', 'first_name', 'last_name', 'email', 'favorite')


user_schema = UserSchema()
multi_user_schema = UserSchema(many=True)

class Post(db.Model):
    
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    
    image = db.Column(db.String, unique=False, nullable=False)
    title = db.Column(db.String(255), unique=False, nullable=False)
    description = db.Column(db.String, unique=False, nullable=False)


    def __init__(self, image, title, description):
        self.image = image
        self.title = title
        self.description = description


class PostSchema(ma.Schema):
    class Meta:
        fields = ('id', 'image', 'title', 'description')


post_schema = PostSchema()
multi_post_schema = PostSchema(many=True)

# ________________
# | admin routes |
# V              V
    
# *VERIFIED* Endpoint to add an admin
@app.route('/admin/add', methods=['POST'])
def add_admin():
    if request.content_type != 'application/json':
        return jsonify('Error: This is embarrassing...maybe you should, I dunno...TRY IT AS JSON!')

    post_data = request.get_json()
    email = post_data.get('email')
    password = post_data.get('password')

    if email == None:
        return jsonify('Error: Provide A email, ya DINGUS!')
    if password == None:
        return jsonify('Error: Provide A Password, ya DINGUS!')
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')


    new_admin = Admin(email, pw_hash)
    db.session.add(new_admin)
    db.session.commit()

    return jsonify(user_schema.dump(new_admin))

# *VERIFIED* Admin Login Endpoint    
@app.route('/login', methods=['POST'])
def login():
    
    post_data = request.get_json()
    email = post_data.get('email', None)
    password = post_data.get('password', None)
    
    admin = db.session.query(Admin).filter(Admin.email == email).first()
    
    if email != admin.email or not bcrypt.check_password_hash(admin.password, password):
        return jsonify({'Error: Username/Password Incorrect!'}), 401
    
    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token)

# *VERIFIED* Endpoint to Query All Admins
@app.route('/admin-roster', methods=['GET'])
def get_all_admins():
    all_admins = db.session.query(Admin).all()
    return jsonify(multi_admin_schema.dump(all_admins))

# *VERIFIED* Endpoint to query one admin
@app.route('/admin/get/<id>', methods=['GET'])
def get_admin_id(id):
    one_admin = db.session.query(Admin).filter(Admin.id == id).first()
    return jsonify(user_schema.dump(one_admin))

# *VERIFIED* Endpoint to delete an admin
@app.route('/admin/delete/<id>', methods=['DELETE'])
def admin_to_delete(id):
    delete_admin = db.session.query(Admin).filter(Admin.id == id).first()
    db.session.delete(delete_admin)
    db.session.commit()
    return jsonify("You are not the Admin you once were...You're GONE!")

# *VERIFIED* Endpoint to update an Admin's email
@app.route('/admin/update/<id>', methods=['PUT'])
def update_admin(id):
    if request.content_type != 'application/json':
        return jsonify('Error: This is embarrassing...maybe you should, I dunno...TRY IT AS JSON!')

    put_data = request.get_json()
    email = put_data.get('email')
    password = put_data.get('password')

    admin = db.session.query(Admin).filter(Admin.id == id).first()

    if email != email or email == None or not bcrypt.check_password_hash(admin.password, password):
        return jsonify('Bruh, really? You gotta gimme somethin\'!')
    if email != None and bcrypt.check_password_hash(admin.password, password):
        admin.email = email

    db.session.commit()
    return jsonify(user_schema.dump(admin))

# *VERIFIED* Endpoint to reset admin password
@app.route('/password/reset/<id>', methods=['PUT'])
def reset_password(id):
    if request.content_type != 'application/json':
        return jsonify('Error: This is embarrassing...maybe you should, I dunno...TRY IT AS JSON!')

    admin = db.session.query(Admin).filter(Admin.id == id).first()
    
    password = request.get_json().get("password")
    pw_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    admin.password = pw_hash
    
    db.session.commit()
    return jsonify(user_schema.dump(admin))
    
# ________________
# | user routes |
# V              V
# // TODO //
# Endpoint to user dashboard
# @app.route('/dashboard')
# def dashboard():
#     if not session.get('logged_in'):
#         return jsonify('You must log in.')
#     else:
#         return jsonify('You are logged in!')

# *VERIFIED* Endpoint to sign up a user
@app.route('/sign-up', methods=['POST'])
def sign_up():
    if request.content_type != 'application/json':
        return jsonify('Error: YO! Send YO data as JSON!')

    post_data = request.get_json()
    first_name = post_data.get('first_name')
    last_name = post_data.get('last_name')
    email = post_data.get('email')
    favorite = post_data.get('favorite')

    if first_name == None:
        return jsonify('Error: Thou Shalt Provide A First Name!')
    if last_name == None:
        return jsonify('Error: Thou Shalt Provide A Last Name!')
    if email == None:
        return jsonify('Error: Thou Shalt Provide A Valid Email Address!')

    new_user = User(first_name, last_name, email, favorite)
    db.session.add(new_user)
    db.session.commit()

    return jsonify(user_schema.dump(new_user))

# *VERIFIED* Endpoint to query all users
@app.route('/users', methods=['GET'])
def get_all_users():
    all_records = db.session.query(User).all()
    return jsonify(multi_user_schema.dump(all_records))

# *VERIFIED* Endpoint to query one user
@app.route('/user/<email>', methods=['GET'])
def get_user_id(email):
    one_user = db.session.query(User).filter(User.email == email).first()
    return jsonify(user_schema.dump(one_user))

# *VERIFIED* Endpoint to delete a user
@app.route('/unsubscribe/<email>', methods=['DELETE'])
def unsubscribe_user(email):
    delete_user = db.session.query(User).filter(User.email == email).first()
    db.session.delete(delete_user)
    db.session.commit()
    return jsonify("The user you chose is POOF! Gone, done, DELETED!")

# *VERIFIED* Endpoint to update/edit a user
@app.route('/user/update/<email>', methods=['PUT'])
def update_user(email):
    if request.content_type != 'application/json':
        return jsonify('Error: data must be sent as JSON!')
    
    user = db.session.query(User).filter(User.email == email).first()

    put_data = request.get_json()
    first_name = put_data.get('first_name')
    last_name = put_data.get('last_name')
    email = put_data.get('email')


    if first_name and last_name and email == None:
        return jsonify("Uh, you can't do that...send something to update!")
    if first_name != None:
        user.first_name = first_name
    if last_name != None:
        user.last_name = last_name
    if email != None:
        user.email = email

    db.session.commit()
    return jsonify(user_schema.dump(user))

# ________________
# | post routes |
# V             V

# *VERIFIED* Endpoint to add a post
@app.route('/post', methods=['POST'])
def add_post():
    if request.content_type != 'application/json':
        return jsonify('Error: This is embarrassing...maybe you should, I dunno...TRY IT AS JSON!')

    post_data = request.get_json()
    image = post_data.get('image')
    title = post_data.get('title')
    description = post_data.get('description')

    if image == None:
        return jsonify('Error: Provide An Image, ya DINGUS!')
    if title == None:
        return jsonify('Error: Provide A Title, ya DINGUS!')
    if description == None:
        return jsonify('Error: Provide A Description, ya DINGUS!')

    new_post = Post(image, title, description)
    db.session.add(new_post)
    db.session.commit()

    return jsonify(post_schema.dump(new_post))

# *VERIFIED* Endpoint to query all posts
@app.route('/posts', methods=['GET'])
def get_posts():
    all_posts = db.session.query(Post).all()
    return jsonify(multi_post_schema.dump(all_posts))

# *VERIFIED* Endpoint to query one post
@app.route('/post/<id>', methods=['GET'])
def get_post(id):
    one_post = db.session.query(Post).filter(Post.id == id).first()
    return jsonify(post_schema.dump(one_post))

# *VERIFIED* Endpoint to delete a post
@app.route('/delete/<id>', methods=['DELETE'])
def delete_post(id):
    delete_post = db.session.query(Post).filter(Post.id == id).first()
    db.session.delete(delete_post)
    db.session.commit()
    return jsonify("The post you chose is POOF! Gone, done, DELETED!")

# *VERIFIED* Endpoint to update/edit a post
@app.route('/post/update/<id>', methods=['PUT'])
def update_post(id):
    if request.content_type != 'application/json':
        return jsonify('Error: data must be sent as JSON!')
    
    updated_post = db.session.query(Post).filter(Post.id == id).first()

    put_data = request.get_json()
    image = put_data.get('image')
    title = put_data.get('title')
    description = put_data.get('description')


    if image and title and description == None:
        return jsonify("Uh, you can't do that...send something to update!")
    if image != None:
        updated_post.image = image
    if title != None:
        updated_post.title = title
    if description != None:
        updated_post.description = description
        
    db.session.add(updated_post)    
    db.session.commit()
    return jsonify(user_schema.dump(updated_post))

if __name__ == '__main__':
    app.run(debug=True)