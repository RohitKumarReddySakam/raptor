import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "raptor-edr-dev-2025")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///raptor.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
    DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() == "true"
