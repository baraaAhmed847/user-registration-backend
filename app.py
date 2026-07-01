from flask_cors import CORS, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
app = Flask(__name__)

from dotenv import load_dotenv
import os
import secrets
import traceback
import resend

load_dotenv()

resend.api_key = os.getenv("RESEND_API_KEY")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# السماح بالمنافذ المحلية ومنافذ ريلواي مستقبلاً
CORS(
    app,
    resources={"/api/*": {
        "origins": "https://user-registration-frontend-production.up.railway.app"
    }}
)
reset_tokens = {}

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
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


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not name or not email or not password or not confirm_password:
        return jsonify({"error": "من فضلك اكتب كل البيانات المطلوبة"}), 400

    if password != confirm_password:
        return jsonify({"error": "كلمتا المرور غير متطابقتين"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "البريد الإلكتروني مستخدم قبل كده"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(name=name, email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "تم إنشاء الحساب بنجاح", "user": new_user.to_dict()}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "من فضلك اكتب كل البيانات المطلوبة"}), 400

    user = User.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        return jsonify({"error": "البريد الإلكتروني أو كلمة المرور غير صحيحة"}), 401

    access_token = create_access_token(identity=str(user.id))
    return jsonify({"message": "تم تسجيل الدخول بنجاح", "token": access_token, "user": user.to_dict()}), 200


@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "المستخدم غير موجود"}), 404

    return jsonify(user.to_dict()), 200


@app.route('/api/profile', methods=['PUT'])
@jwt_required()
def update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "المستخدم غير موجود"}), 404

    data = request.get_json()
    new_name = data.get('name')
    new_email = data.get('email')
    bio = data.get('bio')

    if new_email and new_email != user.email:
        if User.query.filter_by(email=new_email).first():
            return jsonify({"error": "البريد الإلكتروني مستخدم قبل كده"}), 400
        user.email = new_email

    if new_name:
        user.name = new_name

    if bio is not None:
        user.bio = bio

    db.session.commit()
    return jsonify({"message": "تم التعديل بنجاح", "user": user.to_dict()}), 200


@app.route('/api/change-password', methods=['PUT'])
@jwt_required()
def change_password():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "المستخدم غير موجود"}), 404

    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    if not old_password or not new_password or not confirm_new_password:
        return jsonify({"error": "من فضلك اكتب كل البيانات المطلوبة"}), 400

    if not bcrypt.check_password_hash(user.password_hash, old_password):
        return jsonify({"error": "كلمة المرور القديمة غير صحيحة"}), 401

    if new_password != confirm_new_password:
        return jsonify({"error": "كلمتا المرور غير متطابقتين"}), 400

    user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    return jsonify({"message": "تم تغيير كلمة المرور بنجاح"}), 200


@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({"message": "تم تسجيل الخروج بنجاح"}), 200


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "البريد الإلكتروني غير موجود"}), 404

    token = secrets.token_urlsafe(16)
    reset_tokens[token] = {
        "user_id": user.id,
        "expires_at": __import__('time').time() + 900
    }

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
    except Exception as e:
        traceback.print_exc()
        return jsonify({"error": f"فشل إرسال الإيميل: {str(e)}"}), 500

    return jsonify({"message": "تم إرسال رابط إعادة التعيين على بريدك الإلكتروني"}), 200


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')

    if token not in reset_tokens:
        return jsonify({"error": "الرابط غير صحيح أو منتهي الصلاحية"}), 400

    token_data = reset_tokens[token]
    if __import__('time').time() > token_data['expires_at']:
        reset_tokens.pop(token)
        return jsonify({"error": "انتهت صلاحية الرابط، اطلب رابطاً جديداً"}), 400

    if new_password != confirm_new_password:
        return jsonify({"error": "كلمتا المرور غير متطابقتين"}), 400

    user_id = reset_tokens.pop(token)['user_id']
    user = User.query.get(user_id)

    if not user:
        return jsonify({"error": "المستخدم غير موجود"}), 404

    user.password_hash = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    return jsonify({"message": "تم تغيير كلمة المرور بنجاح"}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # لتسهيل التشغيل على ريلواي يفضل قراءة البورت من البيئة
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)