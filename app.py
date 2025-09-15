from flask import Flask, request, render_template_string, redirect, url_for, flash
import os
from werkzeug.utils import secure_filename
from PIL import Image
from PIL.ExifTags import TAGS
from mako.template import Template
import tempfile

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'svg'}

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

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

@app.route('/')
def index():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Image Analyzer</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }
            .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            h1 { color: #333; text-align: center; }
            .upload-form { margin: 20px 0; }
            input[type="file"] { margin: 10px 0; padding: 10px; border: 2px dashed #ccc; width: 100%; }
            input[type="submit"] { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 5px; cursor: pointer; font-size: 16px; }
            input[type="submit"]:hover { background: #0056b3; }
            .flash-messages { margin: 20px 0; }
            .flash-error { color: #d32f2f; background: #ffebee; padding: 10px; border-radius: 5px; }
            .flash-success { color: #388e3c; background: #e8f5e8; padding: 10px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Upload Image</h1>
            <div class="flash-messages">
                {% for message in get_flashed_messages() %}
                    <div class="flash-error">{{ message }}</div>
                {% endfor %}
            </div>
            <form class="upload-form" method="post" action="{{ url_for('upload_file') }}" enctype="multipart/form-data">
                <p>Select an image file to upload (JPG, PNG, SVG):</p>
                <input type="file" name="file" accept=".jpg,.jpeg,.png,.svg" required>
                <br>
                <input type="submit" value="Upload Image">
            </form>
        </div>
    </body>
    </html>
    """)

@app.route('/upload', methods=['POST'])
def upload_file():
    with open('/tmp/debug.log', 'a') as f:
        f.write("DEBUG: Upload function called\n")
        f.flush()
    if 'file' not in request.files:
        flash('No file selected')
        return redirect(url_for('index'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No file selected')
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
            flash(f'Error processing image: {str(e)}')
            return redirect(url_for('index'))
    
    else:
        flash('Invalid file type. Please upload JPG, PNG, or SVG files only.')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)