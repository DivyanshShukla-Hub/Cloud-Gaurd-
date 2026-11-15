import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cloudguard-dev-secret-key-2026')
    DATABASE = os.environ.get('DATABASE_PATH', 'cloudguard.db')
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads')
    MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1MB limit
    ALLOWED_EXTENSIONS = {'json', 'yaml', 'yml'}
    
    # Disable browser caching of static assets & force template auto-reload
    SEND_FILE_MAX_AGE_DEFAULT = 0
    TEMPLATES_AUTO_RELOAD = True