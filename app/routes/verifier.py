from flask import Blueprint, render_template

verifier_bp = Blueprint('verifier', __name__, url_prefix='/verifier')

@verifier_bp.route('/login')
def login():
    return render_template('verifier/login.html')

@verifier_bp.route('/dashboard')
def dashboard():
    return render_template('verifier/dashboard.html')

@verifier_bp.route('/report_detail')
def report_detail():
    return render_template('verifier/report_detail.html')