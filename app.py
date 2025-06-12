import sys
import asyncio
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
import re
from markupsafe import Markup

# Load environment variables from .env file if it exists
load_dotenv()

# Windows 환경에서는 WindowsSelectorEventLoopPolicy를 사용하도록 설정
if sys.platform.startswith('win'):
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from flask import Flask, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman

from config import Config
from database import db
from modules import utils

# Import all blueprint modules
from modules.auth import auth_bp
from modules.user import user_bp
from modules.posts import posts_bp
from modules.news import news_bp
from modules.problems import problems_bp
from modules.roadmap import roadmap_bp
from modules.admin import admin_bp
from modules.jeongchgi import jeongchgi_bp

app = Flask(__name__)
app.config.from_object(Config)

# Set maximum content length from environment variable or default to 100MB
max_upload_size = os.environ.get('MAX_UPLOAD_SIZE', 100)
app.config['MAX_CONTENT_LENGTH'] = int(max_upload_size) * 1024 * 1024

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Configure security headers with Talisman 
talisman = Talisman(
    app,
    content_security_policy={
        'default-src': ["'self'"],
        'script-src': [
            "'self'", 
            "'unsafe-inline'", 
            "'unsafe-eval'", 
            "cdn.jsdelivr.net", 
            "cdnjs.cloudflare.com"
        ],
        'style-src': [
            "'self'", 
            "'unsafe-inline'", 
            "cdnjs.cloudflare.com", 
            "fonts.googleapis.com", 
            "cdn.jsdelivr.net"
        ],
        'img-src': ["'self'", 'data:', '*'],
        'font-src': [
            "'self'", 
            'data:', 
            "cdnjs.cloudflare.com", 
            "fonts.googleapis.com", 
            "fonts.gstatic.com", 
            "cdn.jsdelivr.net",
            "*.jsdelivr.net"
        ],
        'connect-src': ["'self'", "cdn.jsdelivr.net"]
    },
    force_https=False,  # Set to True in production with HTTPS
    session_cookie_secure=True,
    session_cookie_http_only=True,
    frame_options='SAMEORIGIN'
)

# Use ProxyFix if behind a reverse proxy
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

# Initialize database
db.init_app(app)

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(posts_bp)
app.register_blueprint(news_bp)
app.register_blueprint(problems_bp)
app.register_blueprint(roadmap_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(jeongchgi_bp)

# Setup upload folder
UPLOAD_FOLDER = os.path.join(app.root_path, 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Set global utils variables
utils.UPLOAD_FOLDER = UPLOAD_FOLDER
utils.MAX_CONTENT_LENGTH = app.config['MAX_CONTENT_LENGTH']

# Helper functions
def nl2br(value):
    # XSS 방지를 위해 Markup.escape 사용
    return Markup(re.sub(r'\n', '<br>\n', Markup.escape(value)))

app.jinja_env.filters['nl2br'] = nl2br

# 모든 사용자 입력값 이스케이프 처리 설정
app.jinja_env.autoescape = True

# Error handlers
@app.errorhandler(400)
def handle_csrf_error(e):
    return render_template('error.html', title="Error - 400", error_code=400, 
                          message="CSRF 검증에 실패했습니다. 페이지를 새로고침하고 다시 시도해주세요."), 400

@app.errorhandler(404)
async def page_not_found(e):
    return render_template('error.html', title="Error - 404", error_code=404, message="페이지를 찾을 수 없습니다."), 404

@app.errorhandler(500)
async def internal_server_error(e):
    return render_template('error.html', title="Error - 500", error_code=500, message="내부 서버 오류가 발생했습니다."), 500

# Route for image upload (used by CKEditor)
@app.route('/upload_image', methods=['POST'])
@csrf.exempt  # Exempt for CKEditor compatibility
async def upload_image():
    from flask import jsonify
    
    if 'upload' not in request.files:
        return jsonify({"error": "파일이 업로드되지 않았습니다."}), 400

    file = request.files['upload']
    if file.filename == '':
        return jsonify({"error": "선택된 파일이 없습니다."}), 400

    if not utils.allowed_file(file.filename):
        return jsonify({"error": "허용되지 않는 파일 형식입니다."}), 400

    # Check file size
    file_content = file.read()
    file.seek(0)
    
    if len(file_content) > utils.MAX_CONTENT_LENGTH:
        return jsonify({"error": f"파일 크기는 {utils.MAX_CONTENT_LENGTH//1024//1024}MB 이하여야 합니다."}), 400
    
    # Validate file content
    file_ext = utils.validate_image(file)
    if not file_ext:
        return jsonify({"error": "유효하지 않은 이미지 형식입니다."}), 400
    
    unique_filename = utils.save_uploaded_image(file)
    from flask import url_for
    image_url = url_for('static', filename='uploads/' + unique_filename, _external=True)
    return jsonify({"url": image_url})

# Main index route
@app.route('/')
async def index():
    from database import Announcement
    posts = await asyncio.to_thread(lambda: Announcement.query.order_by(Announcement.id.desc()).limit(3).all())
    return render_template('index.html', posts=posts)

# Password reset enforcement middleware
@app.before_request
async def enforce_password_reset():
    from flask import session, flash, redirect, url_for
    from database import User
    
    if 'logged_in' in session:
        user = await asyncio.to_thread(lambda: db.session.get(User, session['user_id']))
        if user:
            session['role'] = user.role
            if user.is_suspended:
                flash("계정이 정지되어 있어 로그아웃됩니다.", "danger")
                session.clear()
                return redirect(url_for('auth.login'))
            if user.force_password_reset:
                allowed_endpoints = ['auth.force_change_password', 'auth.logout', 'static']
                if request.endpoint not in allowed_endpoints:
                    flash("비밀번호 초기화가 완료될 때까지 다른 페이지에 접근할 수 없습니다.", "danger")
                    return redirect(url_for('auth.force_change_password'))

if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=80)
