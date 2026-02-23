import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SQLALCHEMY_DATABASE_URI = (
        f"mysql+pymysql://{os.getenv('MYSQL_USER')}:{os.getenv('MYSQL_PASSWORD')}@"
        f"{os.getenv('MYSQL_HOST')}/{os.getenv('MYSQL_DATABASE')}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv('SECRET_KEY') or 'dev_secret_key'
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY') or 'change_this_to_a_real_secret'
    JWT_ACCESS_TOKEN_EXPIRES = False  # for testing

    # 📸 Upload settings (added safely)
    UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
    ALLOWED_EXT = {'png', 'jpg', 'jpeg'}