from flask import Flask, request, render_template_string, redirect, url_for, flash, make_response
import os
from werkzeug.utils import secure_filename
from PIL import Image
from PIL.ExifTags import TAGS
from mako.template import Template
import tempfile
import hashlib
import gzip
import base64
import json
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# Initialize Flask-Limiter with IP-specific banning for one minute
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["5 per minute"],
    storage_uri="memory://",
    strategy="moving-window",
    headers_enabled=True,
    swallow_errors=False
)
limiter.init_app(app)
# app.secret_key = 'your-secret-key-here'  # Commented out to avoid session conflicts
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'svg'}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Simple user database (in production, use a real database)
USERS = {
    'admin': '679cc4492bacfd74128e032dd1c89c53',  # Admin password
}

# Authentication functions
def create_session_cookie(username, role):
    """Create session cookie in format: username:md5(role) -> gzip -> base64 -> ascii hex"""
    role_hash = hashlib.md5(role.encode()).hexdigest()
    session_data = f"{username}:{role_hash}"
    compressed = gzip.compress(session_data.encode())
    base64_encoded = base64.b64encode(compressed).decode()
    # Convert to ASCII hex representation
    hex_encoded = ''.join(format(ord(char), '02x') for char in base64_encoded)
    return hex_encoded

def decode_session_cookie(cookie_value):
    """Decode session cookie and return username, role"""
    try:
        # Convert hex back to base64
        if len(cookie_value) % 2 != 0:
            return None, None
        base64_encoded = ''.join(chr(int(cookie_value[i:i+2], 16)) for i in range(0, len(cookie_value), 2))
        
        decoded = base64.b64decode(base64_encoded.encode())
        decompressed = gzip.decompress(decoded).decode()
        username, role_hash = decompressed.split(':', 1)
        
        # Check if it's admin role
        admin_hash = hashlib.md5('admin'.encode()).hexdigest()
        user_hash = hashlib.md5('user'.encode()).hexdigest()
        
        if role_hash == admin_hash:
            return username, 'admin'
        elif role_hash == user_hash:
            return username, 'user'
        else:
            return None, None
    except:
        return None, None

def require_admin(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_cookie = request.cookies.get('session')
        if not session_cookie:
            return redirect(url_for('login'))
        
        username, role = decode_session_cookie(session_cookie)
        if role != 'admin':
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

# Custom error handler for rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    """Custom HTML response for rate limit exceeded"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rate Limit Exceeded</title>
        <style>
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0;
                padding: 0;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
            }
            .banner {
                background: white;
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                padding: 40px;
                text-align: center;
                max-width: 500px;
                margin: 20px;
                animation: slideIn 0.5s ease-out;
            }
            @keyframes slideIn {
                from { transform: translateY(-50px); opacity: 0; }
                to { transform: translateY(0); opacity: 1; }
            }
            .warning-icon {
                font-size: 4rem;
                color: #ff6b6b;
                margin-bottom: 20px;
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0%, 100% { transform: scale(1); }
                50% { transform: scale(1.1); }
            }
            h1 {
                color: #2c3e50;
                margin-bottom: 20px;
                font-size: 2rem;
                font-weight: 600;
            }
            .message {
                color: #555;
                font-size: 1.1rem;
                line-height: 1.6;
                margin-bottom: 30px;
            }
            .countdown {
                background: #ff6b6b;
                color: white;
                padding: 15px 30px;
                border-radius: 25px;
                font-size: 1.2rem;
                font-weight: bold;
                display: inline-block;
                margin-bottom: 20px;
            }
            .info {
                background: #f8f9fa;
                border-left: 4px solid #007bff;
                padding: 15px;
                margin: 20px 0;
                border-radius: 5px;
                text-align: left;
            }
            .retry-btn {
                background: #007bff;
                color: white;
                padding: 12px 30px;
                border: none;
                border-radius: 25px;
                font-size: 1rem;
                cursor: pointer;
                transition: background 0.3s;
                text-decoration: none;
                display: inline-block;
                margin-top: 20px;
            }
            .retry-btn:hover {
                background: #0056b3;
            }
        </style>
    </head>
    <body>
        <div class="banner">
            <div class="warning-icon">⚠️</div>
            <h1>You're Banned for 1 Minute!</h1>
            <div class="message">
                You have exceeded the rate limit of <strong>5 requests per minute</strong>.
                <br>Your IP address has been temporarily blocked.
            </div>
            <div class="countdown">Please wait 60 seconds to continue</div>
            <div class="info">
                <strong>Rate Limit Policy:</strong><br>
                • Maximum 5 requests per minute per IP<br>
                • Block duration: 1 minute<br>
                • This helps protect our servers from abuse
            </div>
            <a href="javascript:location.reload()" class="retry-btn">Retry</a>
        </div>
        <script>
            // Auto-refresh after 60 seconds
            setTimeout(function() {
                location.reload();
            }, 60000);
        </script>
    </body>
    </html>
    """, 429

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_exif_data(image_path):
    """Extract EXIF data from image"""
    try:
        image = Image.open(image_path)
        exifdata = image.getexif()
        
        exif_dict = {}
        for tag_id in exifdata:
            tag = TAGS.get(tag_id, tag_id)
            data = exifdata.get(tag_id)
            if isinstance(data, bytes):
                data = data.decode('utf-8', errors='ignore')
            exif_dict[tag] = data
        
        return exif_dict
    except Exception as e:
        return {"error": str(e)}

def login_template(error_message=''):
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>CTF</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            input[type="submit"] { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; width: 100%; }
            input[type="submit"]:hover { background: #0056b3; }
            .flash-messages { margin: 20px 0; }
            .flash-error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 5px; }
            .flash-success { color: #388e3c; background: #e8f5e8; padding: 10px; border-radius: 5px; }
            .link { text-align: center; margin-top: 20px; }
            .link a { color: #007bff; text-decoration: none; }
            .link a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Login</h1>
            <div class="flash-messages">
                ''' + (f'<div class="flash-error">{error_message}</div>' if error_message else '') + '''
            </div>
            <form method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <input type="submit" value="Login">
            </form>
            <div class="link">
                <a href="''' + url_for('register') + '''">Don't have an account? Register here</a>
            </div>
        </div>
    </body>
    </html>
    '''

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", per_method=True, error_message="Rate limit exceeded. IP banned for 1 minute.")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if user exists and password is correct
        if username in USERS and USERS[username] == password:
            # Determine user role based on username
            if username == 'admin':
                # Admin login
                cookie_value = create_session_cookie(username, 'admin')
                response = make_response(redirect(url_for('index')))
                response.set_cookie('session', cookie_value, path='/', httponly=True)
                return response
            else:
                # Regular user login
                cookie_value = create_session_cookie(username, 'user')
                response = make_response(redirect(url_for('user_dashboard')))
                response.set_cookie('session', cookie_value, path='/', httponly=True)
                return response
        else:
            return render_template_string(login_template('Invalid username or password'))
    
    return render_template_string(login_template())

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute", per_method=True, error_message="Rate limit exceeded. IP banned for 1 minute.")
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Prevent admin registration
        if username.lower() == 'admin':
            return render_template_string(register_template('Cannot register as admin'))
        
        # Check if user already exists
        if username in USERS:
            return render_template_string(register_template('Username already exists'))
        
        # Register new user
        USERS[username] = password
        
        # Create session cookie for normal user
        cookie_value = create_session_cookie(username, 'user')
        response = make_response(redirect(url_for('user_dashboard')))
        response.set_cookie('session', cookie_value, path='/', httponly=True)
        return response
    
    return render_template_string(register_template())

def register_template(error_message=''):
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Register - Image Analyzer</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .form-group { margin: 15px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input[type="text"], input[type="password"] { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 5px; box-sizing: border-box; }
            input[type="submit"] { background: #28a745; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; width: 100%; }
            input[type="submit"]:hover { background: #218838; }
            .flash-messages { margin: 20px 0; }
            .flash-error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 5px; }
            .link { text-align: center; margin-top: 20px; }
            .link a { color: #007bff; text-decoration: none; }
            .link a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Register</h1>
            <div class="flash-messages">
                ''' + (f'<div class="flash-error">{error_message}</div>' if error_message else '') + '''
            </div>
            <form method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <input type="submit" value="Register">
            </form>
            <div class="link">
                <a href="''' + url_for('login') + '''">Already have an account? Login here</a>
            </div>
        </div>
    </body>
    </html>
    '''



@app.route('/user_dashboard')
@limiter.limit("5 per minute", per_method=True, error_message="Rate limit exceeded. IP banned for 1 minute.")
def user_dashboard():
    session_cookie = request.cookies.get('session')
    if not session_cookie:
        return redirect(url_for('login'))
    
    username, role = decode_session_cookie(session_cookie)
    if not username:
        return redirect(url_for('login'))
    
    return render_template_string('''
    <!DOCTYPE html>
    <html>
    <head>
        <title>User Dashboard - Image Analyzer</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .info { background: #e3f2fd; padding: 15px; border-radius: 5px; margin: 20px 0; }
            .admin-link { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; text-align: center; }
            .admin-link a { color: #007bff; text-decoration: none; font-weight: bold; }
            .admin-link a:hover { text-decoration: underline; }
            .logout { text-align: center; margin-top: 20px; }
            .logout a { color: #dc3545; text-decoration: none; }
            .logout a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Welcome, {{ username }}!</h1>
            <div class="info">
                <p><strong>Role:</strong> {{ role }}</p>
                {% if role == 'admin' %}
                    <p>You have admin privileges and can access the image analyzer.</p>
                {% else %}
                    <p>You are logged in as a regular user. Only admin users can access the image analyzer.</p>
                {% endif %}
            </div>
            {% if role == 'admin' %}
            <div class="admin-link">
                <a href="{{ url_for('index') }}">🔧 Access Image Analyzer (Admin Only)</a>
            </div>
            {% endif %}
            <div class="logout">
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </body>
    </html>
    ''', username=username, role=role)

@app.route('/logout')
@limiter.limit("5 per minute", per_method=True, error_message="Rate limit exceeded. IP banned for 1 minute.")
def logout():
    response = make_response(redirect(url_for('login')))
    response.set_cookie('session', '', expires=0)
    return response

@app.route('/')
@require_admin
@limiter.limit("5 per minute", per_method=True, error_message="Rate limit exceeded. IP banned for 1 minute.")
def index():
    session_cookie = request.cookies.get('session')
    username, role = decode_session_cookie(session_cookie)
    
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Image Analyzer - Admin Panel</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .user-info { background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; text-align: center; }
            .upload-form { margin: 20px 0; }
            input[type="file"] { margin: 10px 0; padding: 10px; border: 2px dashed #ccc; width: 100%; }
            input[type="submit"] { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            input[type="submit"]:hover { background: #0056b3; }
            .flash-messages { margin: 20px 0; }
            .flash-error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 5px; }
            .flash-success { color: #388e3c; background: #e8f5e8; padding: 10px; border-radius: 5px; }
            .logout { text-align: center; margin-top: 20px; }
            .logout a { color: #dc3545; text-decoration: none; }
            .logout a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Image Analyzer - Admin Panel</h1>
            <div class="user-info">
                <p><strong>Welcome, {{ username }}!</strong> | Role: {{ role }}</p>
            </div>
            <div class="flash-messages">
                {% for message in get_flashed_messages() %}
                    <div class="flash-success">{{ message }}</div>
                {% endfor %}
            </div>
            <form class="upload-form" method="post" action="{{ url_for('upload_file') }}" enctype="multipart/form-data">
                <p>Select an image file to upload (JPG, PNG, SVG):</p>
                <input type="file" name="file" accept=".jpg,.jpeg,.png,.svg" required>
                <br>
                <input type="submit" value="Upload Image">
            </form>
            <div class="logout">
                <a href="{{ url_for('logout') }}">Logout</a>
            </div>
        </div>
    </body>
    </html>
    """, username=username, role=role)

@app.route('/upload', methods=['POST'])
@require_admin
@limiter.limit("5 per minute", per_method=True, error_message="Rate limit exceeded. IP banned for 1 minute.")
def upload_file():
    with open('/tmp/debug.log', 'a') as f:
        f.write("DEBUG: Upload function called\n")
        f.flush()
    if 'file' not in request.files:
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        return redirect(request.url)
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Extract EXIF data
        exif_data = extract_exif_data(filepath)
        
        # Get image metadata
        try:
            with Image.open(filepath) as img:
                width, height = img.size
                resolution = f"{width} x {height}"
        except:
            resolution = "Unknown"
        
        # Get file size
        file_size = os.path.getsize(filepath)
        if file_size < 1024:
            file_size_str = f"{file_size} bytes"
        elif file_size < 1024 * 1024:
            file_size_str = f"{file_size / 1024:.1f} KB"
        else:
            file_size_str = f"{file_size / (1024 * 1024):.1f} MB"
        
        # Extract specific EXIF fields for display
        author = exif_data.get('Artist', 'Not specified')
        copyright_info = exif_data.get('Copyright', 'Not specified')
        
        # Vulnerable template rendering with EXIF data
        # This is where the SSTI vulnerability exists
        template_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Upload Result</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
                h1 { color: #333; }
                .success { color: #388e3c; background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .exif-data { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
                .exif-item { margin: 10px 0; padding: 10px; background: white; border-left: 4px solid #007bff; }
                .back-link { display: inline-block; margin-top: 20px; color: #007bff; text-decoration: none; }
                .back-link:hover { text-decoration: underline; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Upload Successful!</h1>
                <div class="success">
                    File "${filename}" has been uploaded successfully!
                </div>
                
                <h2>Image Information:</h2>
                <div class="exif-data">
                    <div class="exif-item">
                        <strong>Resolution:</strong> ${resolution}
                    </div>
                    <div class="exif-item">
                        <strong>File Size:</strong> ${file_size_str}
                    </div>
                    <div class="exif-item">
                        <strong>Author:</strong> ${author}
                    </div>
                    <div class="exif-item">
                        <strong>Copyright:</strong> ${copyright_info}
                    </div>
                </div>
                
                <h2>EXIF Data Analysis:</h2>
                <div class="exif-data">
                    % for key, value in exif_data.items():
                        <div class="exif-item">
                            <strong>${key}:</strong> ${value}
                        </div>
                    % endfor
                </div>
                
                <a href="/" class="back-link">← Upload Another Image</a>
            </div>
        </body>
        </html>
        """
        
        # VULNERABLE: Direct template rendering with user-controlled EXIF data
        # EXIF data can contain malicious Mako template code
        with open('/tmp/debug.log', 'a') as f:
            f.write("DEBUG: Starting vulnerable template rendering\n")
            f.flush()
        try:
            # Create vulnerable template by directly injecting EXIF data
            if 'ImageDescription' in exif_data:
                payload = str(exif_data['ImageDescription'])
                with open('/tmp/debug.log', 'a') as f:
                    f.write(f"DEBUG: ImageDescription found: {payload}\n")
                    f.write(f"DEBUG: Contains Mako syntax: {'${' in payload and '}' in payload}\n")
                    f.flush()
                # If payload contains Mako syntax, create a vulnerable template
                if '${' in payload and '}' in payload:
                    with open('/tmp/debug.log', 'a') as f:
                        f.write("DEBUG: Creating vulnerable template\n")
                        f.flush()
                    vulnerable_template = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Upload Result</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; }}
        .success {{ color: #388e3c; background: #e8f5e8; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .exif-data {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }}
        .back-link {{ display: inline-block; margin-top: 20px; color: #007bff; text-decoration: none; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Upload Successful!</h1>
        <div class="success">
            File "{filename}" has been uploaded successfully!
        </div>
        <h2>Image Information:</h2>
        <div class="exif-data">
            <p><strong>Resolution:</strong> {resolution}</p>
            <p><strong>File Size:</strong> {file_size_str}</p>
            <p><strong>Author:</strong> {author}</p>
            <p><strong>Copyright:</strong> {copyright_info}</p>
        </div>
        
        <h2>EXIF Data Analysis:</h2>
        <div class="exif-data">
            <p><strong>ImageDescription:</strong> {payload}</p>
        </div>
        <a href="/" class="back-link">← Upload Another Image</a>
    </div>
</body>
</html>
                    """
                    template = Template(vulnerable_template)
                    return template.render(filename=filename, resolution=resolution, file_size_str=file_size_str, author=author, copyright_info=copyright_info)
            
            # Normal template rendering
            template = Template(template_content)
            rendered = template.render(filename=filename, exif_data=exif_data, resolution=resolution, file_size_str=file_size_str, author=author, copyright_info=copyright_info)
            return rendered
        except Exception as e:
            return redirect(url_for('index'))
    
    else:
        return redirect(url_for('index'))

@app.route('/secret')
@limiter.limit("5 per minute", per_method=True, error_message="Rate limit exceeded. IP banned for 1 minute.")
def secret():
    return "<h1>i am just here to waste your time.</h1>"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)