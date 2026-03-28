from flask import Flask,request,send_from_directory
import secrets
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta,datetime
from models import db
from models import User,Post,Comment,Like,Follow
import random,redis,json
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import os
from werkzeug.utils import secure_filename
from functools import wraps
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity,create_access_token,JWTManager,get_jwt,jwt_required,create_refresh_token
from functools import wraps
from flask import jsonify, g
from flask_cors import CORS
import re

load_dotenv()
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
CORS(app)
app.config['SECRET_KEY'] =os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']= False

app.config['MAIL_SERVER'] = os.getenv("MAIL_SERVER")
app.config['MAIL_PORT'] = int(os.getenv("MAIL_PORT"))
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD")
app.config["UPLOAD_FOLDER"]=UPLOAD_FOLDER

db.init_app(app)
jwt = JWTManager(app)

redis_client = redis.Redis(host="localhost", port=6379, db=0, decode_responses=True)

def jwt_login_required():
    def wrapper(fn):
        @wraps(fn)
        def decorated(*args, **kwargs):

            try:
                verify_jwt_in_request()

                user_id = get_jwt_identity()
                user = User.query.get(user_id)
                jti = get_jwt()['jti']
                if  redis_client.exists(f"blacklist:{jti}"):
                    return jsonify({"msg": "Token has been revoked. Please log in again."}), 401

                if not user:
                    return jsonify({"msg": "User not found"}), 404

    
                g.user = user

            except Exception as e:
                return jsonify({"error": "please login first"}), 401

            return fn(*args, **kwargs)

        return decorated
    return wrapper
otp_store={}
fp_otp_store={}
@app.route("/register")
def show_register():
    try:
        verify_jwt_in_request()
        return jsonify({
            "msg": "Already logged in",
            "allow_register": False
        }), 200
    except Exception as e:
      return jsonify({
            "msg": "Not logged in",
            "allow_register": True
        }), 200



def is_valid_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)


@app.route("/register", methods=["POST"])
def register():
    try:
        data=request.get_json()
        name =data.get("name")
        gmail =data.get("gmail")
        password =data.get("password")
        confirm =data.get("confirm")

        if password != confirm:
            return jsonify({"error":"not match password and confirm password"}),422

        if User.query.filter(User.name == name).first():
            return jsonify({"error":"This username is already register"}),409
    
        if User.query.filter(User.gmail == gmail).first():
            return jsonify({"error":"This gmail is already register"}),409

        if not is_valid_email(gmail):
            return jsonify({"error":"invalid email"}),422
        otp = str(random.randint(100000, 999999))

        temp_token = secrets.token_urlsafe(32)

        otp_data= {
            "gmail": gmail,
            "name": name,
            "password": generate_password_hash(password),
            "otp": generate_password_hash(otp)
            }
        redis_client.setex(f"otp:{temp_token}", 300, json.dumps(otp_data))
        send_otp_email(gmail, otp)
        res=send_otp_email(gmail, otp)
        if res==True:
            return jsonify({
            "msg": "OTP sent",   
            "gmail": gmail,
            "token": temp_token,
            "next": "verify_email"
             }), 200
        else :
            return jsonify({"error":"please check your email id"})
    except Exception as e:
        return jsonify({
            "error":str(e)
        }),500 


def send_otp_email(receiver, otp):
        sender = app.config["MAIL_USERNAME"]
        password = app.config["MAIL_PASSWORD"]

        msg = MIMEText(f"Your OTP for registration is: {otp}")
        msg["Subject"] = "Your OTP Verification Code"
        msg["From"] = sender
        msg["To"] = receiver

        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as server:
                server.starttls()
                server.login(sender, password)
                server.sendmail(sender,receiver, msg.as_string())
                return True
        except Exception as e:
            print("Email Error:", e)
            return False 

@app.route("/verify_email",methods=["POST"])
def verify_otp():
    try:

        data=request.get_json()
        temp_token=data.get("temp_token")
        input_otp=data.get("otp")

        stored = redis_client.get(f"otp:{temp_token}")
        if not stored:
            return jsonify({"error":"invalid token"}),401
        otp_data=json.loads(stored)
        if not check_password_hash(otp_data["otp"], input_otp):
            return jsonify({"error": "Invalid OTP"}), 422
        user=User(name=otp_data["name"],gmail=otp_data['gmail'],password=(otp_data['password']))
        db.session.add(user)
        db.session.commit()
        redis_client.delete(f"otp:{temp_token}")
        return jsonify({"msg": "Email verified successfully",
                    "next": "login"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/resend_otp",methods=["POST"])
def resend_otp():
    try:
        data = request.get_json()
        temp_token = data.get("temp_token")
        
        stored = redis_client.get(f"otp:{temp_token}")
        if not stored:
            return jsonify({"error":"invalid token"}),401
        otp_data = json.loads(stored)
        otp = str(random.randint(100000, 999999))
        otp_data["otp"] = generate_password_hash(otp)
        redis_client.setex(f"otp:{temp_token}", 300, json.dumps(otp_data))
        res=send_otp_email(otp_data["gmail"], otp)
        if res==True:
            return jsonify({
            "msg": "OTP resend",
            "next": "verify_email",   
            "token": temp_token
             }), 200
        else :
            return jsonify({"error":"please check your email id"})  
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/login",methods=["POST"])
def login ():
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            return jsonify({
                "msg": "User already logged in",
                "user_id": user_id,
                "page": "home"
                }), 200

    except Exception as e:
        pass
    data=request.get_json()
    gmail = data.get("gmail")
    password =data.get("password")

    user = User.query.filter_by(gmail=gmail).first()

    if user and check_password_hash(user.password, password):
        access_token = create_access_token(identity=str(user.id),additional_claims={"gmail":user.gmail,
                                                                        "name":user.name},expires_delta=timedelta(minutes=15))
        refresh_token=create_refresh_token(identity=str(user.id),expires_delta=timedelta(days=7))
        return jsonify({"access_token":access_token,
                        "refresh_token":refresh_token,
                        
                        "next":"home"}), 200

    return jsonify({"error": "Invalid credentials"}), 401

@app.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    user_id = get_jwt_identity()

    new_access_token = create_access_token(identity=str(user_id))

    return jsonify({
        "access_token": new_access_token
    }), 200

@app.route("/forgot_password", methods=["POST"])
def forgot_password():
    try:
        data = request.get_json()
        gmail = data.get("gmail")

        user = User.query.filter_by(gmail=gmail).first()

        if not user:
            return jsonify({"error": "Email not registered"}), 404
        if not is_valid_email(gmail):
            return jsonify({"error":"invalid email"}),422

        otp = str(random.randint(100000, 999999))
        temp_token = secrets.token_urlsafe(32)

        fp_data = {"gmail": gmail,"otp": generate_password_hash(otp)}
        redis_client.setex(
            f"fp:{temp_token}",
            600,  # 5 min
            json.dumps(fp_data)
        )
        send_otp_email(gmail, otp)

        return jsonify({
            "msg": "OTP sent",
            "temp_token": temp_token,
            "next": "verify_fp_otp"
            }), 200
    
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route("/verify_fp_otp", methods=["POST"])
def verify_fp_otp():
    try:
        data=request.get_json()
        temp_token=data.get("temp_token")
        input_otp=data.get("otp")

        stored = redis_client.get(f"fp:{temp_token}")
        print(stored)
        if not stored:
            return jsonify({"error":"invalid token"}),401
        fp_data=json.loads(stored)
        if not check_password_hash(fp_data["otp"], input_otp):
            return jsonify({"error": "Invalid OTP"}), 422
        return jsonify({"msg":"email verify successfully",
                        "next":"reset_password"}),200
    except Exception as e:
        return jsonify({"error":str(e)}),500
    

@app.route("/resend_fp_otp",methods=["POST"])
def resend_fp_otp():
    try:
        data = request.get_json()
        temp_token = data.get("temp_token")
        
        stored = redis_client.get(f"fp:{temp_token}")
        if not stored:
            return jsonify({"error":"invalid token"}),401
        fp_data = json.loads(stored)
        otp = str(random.randint(100000, 999999))
        fp_data["otp"] = generate_password_hash(otp)
        redis_client.setex(f"fp:{temp_token}", 300, json.dumps(fp_data))
        res=send_otp_email(fp_data["gmail"], otp)
        if res==True:
            return jsonify({
            "msg": "OTP resend",
            "next": "verify_fp_otp",   
            "token": temp_token
             }), 200
        else :
            return jsonify({"error":"please check your email id"})  
    except Exception as e:
        return jsonify({"error": str(e)}), 401 


@app.route("/reset_password", methods=["PUT"])
def reset_password():
    try:
        data=request.get_json()
        password = data.get("password")
        confirm = data.get("confirm")
        temp_token=data.get("temp_token")

        stored= redis_client.get(f"fp:{temp_token}")
        if not stored:
            return jsonify({"error":"invalid token"}),401
        fp_data = json.loads(stored)
        user = User.query.filter_by(gmail=fp_data["gmail"]).first()
        print(user)
        if password != confirm:
            return jsonify({"error":"password and confrim password does not match"}),422
        user.password = generate_password_hash(password)
        db.session.commit()

        return jsonify({"msg":"password update sucessfully"}),200
    except Exception as e:
        return jsonify({"error":str(e)}),500


@app.route("/home",methods=["GET"])
def home():
    try:
        verify_jwt_in_request(optional=True)
        user_id=(get_jwt_identity())
        if not user_id:
            posts=Post.query.order_by(Post.created_at.desc()).all()
            posts_data=[]
            for post in posts: 
                posts_data.append({
                    "id":post.id,
                    "title":post.title,
                    "content":post.content,
                    "created_at":post.created_at,
                    "image":post.image,
                    "Comment":len(post.comments),
                    "like":len(post.likes)})
            return jsonify({"posts":posts_data}),200
            

        posts = Post.query.filter(Post.user_id != user_id).order_by(Post.created_at.desc()).all()
        posts_data=[]
        for post in posts: 
                posts_data.append({
                    "id":post.id,
                    "author_name":post.author.name,
                    "title":post.title,
                    "user_id":post.user_id,
                    "content":post.content,
                    "created_at":post.created_at,
                    "image":post.image,
                    "comment_count":len(post.comments),
                    "like_count":len(post.likes),
                    "is_following":Follow.query.filter_by(follower_id=int(user_id), following_id=post.user_id).first() is not None,
                    "login": True})
        return jsonify({"posts":posts_data}),200
    except Exception as e:
        return jsonify({"error":str(e)}),500
        
@app.route("/profile",methods=["GET"])
@jwt_login_required()
def profile():
    try:
        user_id=get_jwt_identity()
        user=db.session.get(User,user_id)
        if not user:
            return jsonify({
                "error":"User not found"
            })
        user_bio=user.bio
        user_profile_pic=user.profile_pic
        posts=user.posts
        posts_data=[]
        for post in posts:
            posts_data.append({
                "id":post.id,
                "title":post.title,
                "content":post.content,
                "created_at":post.created_at,
                "image":post.image,
                "comment_count":len(post.comments),
                "like_count":len(post.likes)
            })
    
        followers=len(user.followers)
        following=len(user.following)

        return jsonify({
            "user": {
                "id": user.id,
                "gmail": user.gmail,
                "name":user.name,
                "bio": user.bio,
                "profile_pic": user_profile_pic
            },
            "bio":user_bio,
            "posts": posts_data,
            "followers": followers,
            "following": following,
        }), 200  
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route("/add_blog", methods=["POST"])
@jwt_login_required()
def add_blog():
    try:
        user_id = get_jwt_identity()

        if request.content_type.startswith("application/json"):
            data = request.get_json()
            title = data.get("title")
            content = data.get("content")
            image_url = data.get("image_url")
            image_file = None
        else:
            title = request.form.get("title")
            content = request.form.get("content")
            image_url = request.form.get("image_url")
            image_file = request.files.get("image_file")
        if not title or not content:
            return jsonify({
                "error": "Title and content are required"
            }), 400

        image_path = None
        ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

        if image_file and image_file.filename != "":
            if "." in image_file.filename and image_file.filename.rsplit(".", 1)[1].lower() not in ALLOWED_EXTENSIONS:
                return jsonify({"error":"Invalid file type. Allowed: png, jpg, jpeg, gif, webp"}), 400  
            filename = secure_filename(image_file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image_file.save(save_path)

            image_path = f"uploads/{filename}"


        elif image_url:
            image_path = image_url

    
        new_blog = Post(
            title=title,
            content=content,
            image=image_path,
            created_at=datetime.now(),
            user_id=user_id
        )

        db.session.add(new_blog)
        db.session.commit()

        return jsonify({
            "msg": "Blog created successfully",
            "post": {
                "id": new_blog.id,
                "title": new_blog.title,
                "content": new_blog.content,
                "image": new_blog.image,
                "created_at": new_blog.created_at
            }
        }), 201

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500
    

@app.route("/edit_blog/<int:blog_id>", methods=["GET"])
@jwt_login_required()
def edit_blog(blog_id):
    try:
        user_id=int(get_jwt_identity())
        blog = Post.query.get_or_404(blog_id)

        if blog.user_id !=user_id:
            return jsonify({"error":"Unauthorized"}), 403
        
        return jsonify({"title":blog.title,
                        "content":blog.content,
                        "image":blog.image}),200
    except Exception as e:
        return jsonify({
            "error":str(e)
        }),500
    

@app.route("/update_blog/<int:blog_id>", methods=["PUT"])
@jwt_login_required()
def update_blog(blog_id):
    try:
        user_id = int(get_jwt_identity())

        blog = db.session.get(Post, blog_id)
        if not blog:
            return jsonify({"error": "Blog not found"}), 404

        if blog.user_id != user_id:
            return jsonify({"error": "Unauthorized"}), 403

        if request.content_type.startswith("application/json"):
            data = request.get_json()
            title = data.get("title")
            content = data.get("content")
            image_url = data.get("image_url")
            image_file = None
        else:
            title = request.form.get("title")
            content = request.form.get("content")
            image_url = request.form.get("image_url")
            image_file = request.files.get("image_file")

        if not title or not content:
            return jsonify({
                "error": "Title and content are required"
            }), 400
        if not image_file and not image_url:
            return jsonify({
                "error":"image_file or image_url are required"
            })
        blog.title = title
        blog.content = content
        ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
        if image_file and image_file.filename!= "":
            if "." in image_file.filename and image_file.filename.rsplit(".", 1)[1].lower() not in ALLOWED_EXTENSIONS:
                return jsonify({"error":"Invalid file type. Allowed: png, jpg, jpeg, gif, webp"}), 400
            filename = secure_filename(image_file.filename)
            save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            image_file.save(save_path)

            blog.image = f"uploads/{filename}"

        elif image_url:
            blog.image = image_url

        db.session.commit()

        return jsonify({
            "msg": "Blog updated successfully",
            "blog": {
                "id": blog.id,
                "title": blog.title,
                "content": blog.content,
                "image": blog.image
            }
        }), 200

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500
    
@app.route("/delete_blog/<int:post_id>",methods=["DELETE"])
@jwt_login_required()
def delete_blog(post_id):
    try:
        post=db.session.get(Post,post_id)
        user_id=int(get_jwt_identity())
        if not post:
            return jsonify({"error":"blog not found"}),400
        if post.user_id != user_id:
            return jsonify({"error":"Unauthorized"}),403
        db.session.delete(post)
        db.session.commit()
        return jsonify({"msg":"blog delete sucsessfully"}),200
    except Exception as e:
        return jsonify({"error":str(e)}),500
        


@app.route("/comment/<int:post_id>", methods=["POST"])
@jwt_login_required()
def add_comment(post_id):
    try:    
        data=request.get_json()

        comment_text =data.get("comment")

        if not comment_text or not comment_text.strip():
            return jsonify({"error": "Comment cannot be empty"}), 400
        comment = Comment(comment=comment_text.strip(), post_id=post_id, user_id=get_jwt_identity(),timestamp=datetime.now())
        db.session.add(comment)
        db.session.commit()

        return jsonify({
                "msg": "Comment added successfully",
                "comment": {
                    "id": comment.id,
                    "comment":comment.comment,
                    "post_id":comment.post_id,
                    "user_id":comment.user_id,
                    "created_at":comment.timestamp
                }
            }), 201
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500
    
@app.route("/delete_comment/<int:comment_id>", methods=["DELETE"])
@jwt_login_required()
def delete_comment(comment_id):
    try:
        user_id=int(get_jwt_identity())
        comment = Comment.query.get_or_404(comment_id)

        if comment.user_id != user_id:
            return jsonify({"error":"Unauthorized"}), 403

        db.session.delete(comment)
        db.session.commit()

        return jsonify({"msg": "Comment delete successfully"}), 200
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/edit_comment/<int:comment_id>", methods=["GET"])
@jwt_login_required()
def edit_comment(comment_id):
    try:
        user_id=int(get_jwt_identity())
        comment = Comment.query.get_or_404(comment_id)

        if comment.user_id != user_id:
            return jsonify({"error":"Unauthorized"}), 403

        return jsonify({
                "comment": {
                    "id": comment.id,
                    "comment":comment.comment,
                    "post_id":comment.post_id,
                    "user_id":comment.user_id,
                }
            }), 201
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500
    
@app.route("/update_comment/<int:comment_id>",methods=["PUT"])
@jwt_login_required()
def update_comment(comment_id):
    try:
        user_id=int(get_jwt_identity())
        comment = Comment.query.get_or_404(comment_id)

        if comment.user_id != user_id:
            return jsonify({"error":"Unauthorized"}), 403
        
        data=request.get_json()
        updated_comment=data.get("updated_comment")
        
        comment.comment=updated_comment
        db.session.commit()

        return jsonify({
            "msg": "comment updated successfully",
            "comment": {
                "id": comment.id,
                "comment":comment.comment,
                "post_id": comment.post_id
            }
        }), 200

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500


@app.route("/follow/<int:user_id>", methods=["POST"])
@jwt_login_required()
def follow_user(user_id):
    try:
        current_user_id = int(get_jwt_identity())

        if int(current_user_id) == user_id:
            return jsonify({
                "error": "You cannot follow yourself"
            }), 400

        target_user = db.session.get(User, user_id)
        if not target_user:
            return jsonify({
                "error": "User not found"
            }), 404

        existing = Follow.query.filter_by(
            follower_id=current_user_id,
            following_id=user_id
        ).first()

        if existing:
            db.session.delete(existing)
            db.session.commit()

            return jsonify({
                "msg": "Unfollowed successfully",
                "is_following": False
            }), 200
        else:
            new_follow = Follow(
                follower_id=current_user_id,
                following_id=user_id
            )
            db.session.add(new_follow)
            db.session.commit()

            return jsonify({
                "msg": "Followed successfully",
                "is_following": True
            }), 201

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route("/like/<int:post_id>",methods=["POST"])
@jwt_login_required()
def like_post(post_id):
    try:
        user_id=int(get_jwt_identity())

        existing = Like.query.filter_by(user_id=user_id,post_id=post_id).first()

        if existing:
            db.session.delete(existing)
            db.session.commit()
            return jsonify({"msg":"unliked"}),200
        else:
            db.session.add(Like(user_id=user_id, post_id=post_id))
            db.session.commit()
            return jsonify({"msg":"like",
                            "like":{
                                "post_id":post_id,
                                "user_id":user_id
                                }}),200
        
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

@app.route("/comments/<int:post_id>", methods=["GET"])
@jwt_login_required()
def get_comments(post_id):
    user_id =int( get_jwt_identity())
    comments = Comment.query.filter_by(post_id=post_id)\
        .order_by(Comment.id.desc()).all()
    
    comments=[
        {
            "id": c.id,
            "comment": c.comment,
            "created_at": c.timestamp,
            "user_name":db.session.get(User,c.user_id).name,
            "is_own": user_id == c.user_id if user_id else False
        }
        for c in comments]
    return jsonify({"comment":comments}), 200

@app.route("/get_post/<int:post_id>", methods=["GET"])
def get_post(post_id):
    try:
        verify_jwt_in_request(optional=True)
        user_id = get_jwt_identity()
        if user_id:
            user_id = int(user_id)

        posts = Post.query.filter_by(id=post_id)

        if not posts:
            return jsonify({"error": "Post not found"}), 404

        posts_data=[]
        for post in posts: 
                posts_data.append({
                    "id":post.id,
                    "author_name":post.author.name,
                    "title":post.title,
                    "user_id":post.user_id,
                    "content":post.content,
                    "created_at":post.created_at,
                    "image":post.image,
                    "comment_count":len(post.comments),
                    "Comments": [{
                                    "id": c.id,
                                    "user_id": c.user_id,
                                    "comment": c.comment,
                                    "created_at": c.timestamp
                                    }   
                                    for c in post.comments
                                ],
                    "like_count":len(post.likes),
                    "is_following":Follow.query.filter_by(follower_id=int(user_id), following_id=post.user_id).first() is not None,
                    "login": True})
        return jsonify({"posts":posts_data}),200
        

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logout', methods=['POST'])
@jwt_login_required()
def logout():
    jti = get_jwt()['jti']  
    redis_client.setex(f"blacklist:{jti}", 900, "true") 
    return jsonify({"msg":"Successfully logged out"}),200
    

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)


