import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta, date
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    jwt_required,
    get_jwt,
    get_jwt_identity,
    unset_jwt_cookies
)
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config

# ----------------------------------------------------
# APP SETUP
# ----------------------------------------------------
app = Flask(__name__)
app.config.from_object(Config)
CORS(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

# ----------------------------------------------------
# LOGGING
# ----------------------------------------------------
logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
year_month_dir = os.path.join(logs_dir, date.today().strftime('%Y'), date.today().strftime('%m'))
os.makedirs(year_month_dir, exist_ok=True)
log_file = os.path.join(year_month_dir, f'{date.today()}.log')

log_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
log_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)s [%(module)s:%(lineno)d] %(message)s'))

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)

# ----------------------------------------------------
# MODELS
# ----------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    name = db.Column(db.String(120), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone = db.Column(db.String(20), unique=True, nullable=True)
    address = db.Column(db.String(255), nullable=True)

class TokenBlocklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

# JWT BLOCK-LIST CHECK
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    token = TokenBlocklist.query.filter_by(jti=jti).first()
    return token is not None

# ----------------------------------------------------
# ROUTES
# ----------------------------------------------------

@app.route("/", methods=["GET"])
def test():
    return jsonify({"message": "Hello, World!"})

# GET ALL USERS
@app.route("/users", methods=["GET"])
def get_users():
    users = User.query.all()
    output = []
    for u in users:
        output.append({
            "id": u.id,
            "username": u.username,
            "name": u.name,
            "email": u.email,
            "phone": u.phone,
            "address": u.address
        })
    return jsonify(output), 200

# REGISTER USER
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    # Convert empty strings to None
    name = data.get("name") or None
    email = data.get("email") or None
    phone = data.get("phone") or None
    address = data.get("address") or None

    # Duplicate checks
    if User.query.filter_by(username=username).first():
        return jsonify({"message": "Username already taken"}), 400
    if email and User.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400
    if phone and User.query.filter_by(phone=phone).first():
        return jsonify({"message": "Phone already registered"}), 400

    hashed_password = generate_password_hash(password)

    new_user = User(
        username=username,
        password=hashed_password,
        name=name,
        email=email,
        phone=phone,
        address=address
    )

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201

# LOGIN
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data["username"]).first()

    if not user or not check_password_hash(user.password, data["password"]):
        return jsonify({"message": "Invalid credentials"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify(access_token=access_token)

# PROFILE ROUTE
@app.route("/profile", methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    return jsonify({
        "id": user.id,
        "username": user.username,
        "name": user.name,
        "email": user.email,
        "phone": user.phone,
        "address": user.address
    }), 200

# MAIN
if __name__ == "__main__":
    app.run(debug=True)
