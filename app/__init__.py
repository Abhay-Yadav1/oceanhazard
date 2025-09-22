from flask import Flask
from app.routes.user import user_bp
from app.routes.verifier import verifier_bp
from app.routes.admin import admin_bp
from app.routes.main import main_bp 
import os # Add this import

def create_app():
    app = Flask(__name__, template_folder=os.path.join(os.path.dirname(__file__), '..', 'templates'))
    app.secret_key = "your_secret_key"
    app.register_blueprint(main_bp)      # Register main blueprint first
    app.register_blueprint(user_bp)
    app.register_blueprint(verifier_bp)
    app.register_blueprint(admin_bp)
    return app