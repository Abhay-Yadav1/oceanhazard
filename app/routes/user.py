from flask import Blueprint, render_template

user_bp = Blueprint('user', __name__, url_prefix='/user')

@user_bp.route('/index')
def index():
    return render_template('user/index.html')


@user_bp.route('/')
def landing():
    return render_template('Login.html')  
@user_bp.route('/success')
def success():
    return render_template('user/success.html')