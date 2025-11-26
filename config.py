import os
from datetime import timedelta

class Config:
    # Database
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///test.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # JWT Settings
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your_jwt_secret_key")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)


# ✔ Clean
# ✔ Supports environment variables
# ✔ Works on Render/Local
# ✔ Perfect for production