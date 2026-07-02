import os
import re
import secrets
import traceback
from datetime import datetime, timedelta

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity, get_jwt
)
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv
import resend

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=2)

# Only ever run in debug mode locally, never in production
DEBUG_MODE = os.getenv('FLASK_ENV') == 'development'

CORS(app, resources={r"/api/*": {
    "origins": [os.getenv('FRONTEND_URL', 'https://user-registration-frontend-production.up.railway.app')],
    "supports_credentials": True,
    "allow_headers": ["Content-Type", "Authorization"],
    "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
}})

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # swap for redis:// in a multi-instance deployment
)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    profile_image = db.Column(db.String(255))
    bio = db.Column(db.Text)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "profile_image": self.profile_image,
            "bio": self.bio
        }


class PasswordResetToken(db.Model):
    """Persisted so a Railway restart / multi-worker deploy doesn't lose tokens."""
    __tablename__ = 'password_reset_token'
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


class TokenBlocklist(db.Model):
    """Revoked JWTs, so Logout actually invalidates the token instead of being a no-op."""
    __tablename__ = 'token_blocklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True, unique=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    return db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar() is not None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def validate_password_strength(password):
    if len(password) < 8:
        return "كلمة المرور لازم تكون 8 حروف على الأقل"
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        return "كلمة المرور لازم تحتوي على حروف وأرقام"
    return None


def error(message, code):
    return jsonify({"error": message}), code


def handle_db_error(e):
    db.session.rollback()
    traceback.print_exc()
    return error("حصل خطأ، حاول مرة تانية", 500)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/api/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not name or not email or not password or not confirm_password:
        return error("من فضلك اكتب كل البيانات المطلوبة", 400)

    if not EMAIL_RE.match(email):
        return error("البريد الإلكتروني غير صحيح", 400)

    if password != confirm_password:
        return error("كلمتا المرور غير متطابقتين", 400)

    strength_error = validate_password_strength(password)
    if strength_error:
        return error(strength_error, 400)

    try:
        if User.query.filter_by(email=email).first():
            return error("البريد الإلكتروني مستخدم قبل كده", 400)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(name=name, email=email, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()
    except Exception as e:
        return handle_db_error(e)

    access_token = create_access_token(identity=str(new_user.id))
    return jsonify({
        "message": "تم إنشاء الحساب بنجاح",
        "token": access_token,
        "user": new_user.to_dict()
    }), 201


@app.route('/api/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password')

    if not email or not password:
        return error("من فضلك اكتب كل البيانات المطلوبة", 400)

    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        return handle_db_error(e)

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return error("البريد الإلكتروني أو كلمة المرور غير صحيحة", 401)

    access_token = create_access_token(identity=str(user.id))
    return jsonify({
        "message": "تم تسجيل الدخول بنجاح",
        "token": access_token,
        "user": user.to_dict()
    }), 200


@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return error("المستخدم غير موجود", 404)

    return jsonify(user.to_dict()), 200


@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return error("المستخدم غير موجود", 404)

    data = request.get_json(silent=True) or {}
    new_name = (data.get('name') or '').strip() or None
    new_email = (data.get('email') or '').strip().lower() or None
    bio = data.get('bio')
    profile_image = data.get('profile_image')

    if new_email and new_email != user.email:
        if not EMAIL_RE.match(new_email):
            return error("البريد الإلكتروني غير صحيح", 400)
        try:
            if User.query.filter_by(email=new_email).first():
                return error("البريد الإلكتروني مستخدم قبل كده", 400)
        except Exception as e:
            return handle_db_error(e)
        user.email = new_email

    if new_name:
        user.name = new_name

    if bio is not None:
        user.bio = bio

    if profile_image is not None:
        user.profile_image = profile_image

    try:
        db.session.commit()
    except Exception as e:
        return handle_db_error(e)

    return jsonify({"message": "تم التعديل بنجاح", "user": user.to_dict()}), 200


@app.route('/api/change-password', methods=['PUT'])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return error("المستخدم غير موجود", 404)

    data = request.get_json(silent=True) or {}
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    if not old_password or not new_password or not confirm_new_password:
        return error("من فضلك اكتب كل البيانات المطلوبة", 400)

    if not bcrypt.check_password_hash(user.password_hash, old_password):
        return error("كلمة المرور القديمة غير صحيحة", 401)

    if new_password != confirm_new_password:
        return error("كلمتا المرور غير متطابقتين", 400)

    strength_error = validate_password_strength(new_password)
    if strength_error:
        return error(strength_error, 400)

    try:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
    except Exception as e:
        return handle_db_error(e)

    return jsonify({"message": "تم تغيير كلمة المرور بنجاح"}), 200


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    try:
        db.session.add(TokenBlocklist(jti=jti))
        db.session.commit()
    except Exception as e:
        return handle_db_error(e)
    return jsonify({"message": "تم تسجيل الخروج بنجاح"}), 200


@app.route('/api/forgot-password', methods=['POST'])
@limiter.limit("5 per hour")
def forgot_password():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()

    if not email:
        return error("من فضلك اكتب كل البيانات المطلوبة", 400)

    try:
        user = User.query.filter_by(email=email).first()
    except Exception as e:
        return handle_db_error(e)

    # Respond identically whether or not the email exists, to avoid leaking
    # which addresses are registered.
    generic_response = jsonify({
        "message": "لو البريد الإلكتروني موجود، هيوصلك رابط إعادة التعيين"
    }), 200

    if not user:
        return generic_response

    token = secrets.token_urlsafe(32)
    try:
        db.session.add(PasswordResetToken(
            token=token,
            user_id=user.id,
            expires_at=datetime.utcnow() + timedelta(minutes=15)
        ))
        db.session.commit()
    except Exception as e:
        return handle_db_error(e)

    reset_link = f"{os.getenv('FRONTEND_URL')}/reset-password/{token}"

    try:
        resend.Emails.send({
            "from": "My App <onboarding@resend.dev>",
            "to": [email],
            "subject": "إعادة تعيين كلمة المرور",
            "html": f"""
                <div style="font-family:Arial;direction:rtl;text-align:right">
                    <h2>مرحباً {user.name}</h2>
                    <p>لإعادة تعيين كلمة المرور اضغط على الزر:</p>
                    <a href="{reset_link}"
                       style="display:inline-block;padding:10px 20px;
                       background:#287791;color:white;text-decoration:none;
                       border-radius:25px;">
                       إعادة تعيين كلمة المرور
                    </a>
                    <p style="margin-top:20px;font-size:12px;color:#666;">
                        هذا الرابط صالح لمدة 15 دقيقة فقط.
                        إذا لم تطلب ذلك، تجاهل هذا الإيميل.
                    </p>
                </div>
            """
        })
    except Exception:
        # Don't leak email-provider errors to the client; log server-side only.
        traceback.print_exc()

    return generic_response


@app.route('/api/reset-password', methods=['POST'])
@limiter.limit("10 per hour")
def reset_password():
    data = request.get_json(silent=True) or {}
    token = data.get('token')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    if not token or not new_password or not confirm_new_password:
        return error("من فضلك اكتب كل البيانات المطلوبة", 400)

    try:
        token_row = PasswordResetToken.query.filter_by(token=token, used=False).first()
    except Exception as e:
        return handle_db_error(e)

    if not token_row:
        return error("الرابط غير صحيح أو منتهي الصلاحية", 400)

    if datetime.utcnow() > token_row.expires_at:
        return error("انتهت صلاحية الرابط، اطلب رابطاً جديداً", 400)

    if new_password != confirm_new_password:
        return error("كلمتا المرور غير متطابقتين", 400)

    strength_error = validate_password_strength(new_password)
    if strength_error:
        return error(strength_error, 400)

    user = User.query.get(token_row.user_id)
    if not user:
        return error("المستخدم غير موجود", 404)

    try:
        user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
        token_row.used = True
        db.session.commit()
    except Exception as e:
        return handle_db_error(e)

    return jsonify({"message": "تم تغيير كلمة المرور بنجاح"}), 200


@app.errorhandler(404)
def not_found(e):
    return error("الصفحة غير موجودة", 404)


@app.errorhandler(500)
def internal_error(e):
    return error("حصل خطأ، حاول مرة تانية", 500)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=DEBUG_MODE, host='0.0.0.0', port=port)