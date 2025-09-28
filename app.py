from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
import os
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# MySQL Database Configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'root',
    'database': 'ocean_hazards_db',
    'auth_plugin': 'mysql_native_password'
}

def get_db_connection():
    try:
        connection = mysql.connector.connect(**db_config)
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/signup', methods=['POST'])
def signup():
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    full_name = request.form.get('full_name')
    phone = request.form.get('phone')
    location = request.form.get('location')
    
    print(f"DEBUG: Signup attempt - Username: {username}, Email: {email}")
    
    # Check if passwords match
    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('index'))
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Check if username already exists
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            if cursor.fetchone():
                flash('Username already exists', 'error')
                return redirect(url_for('index'))
            
            # Check if email already exists
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash('Email already exists', 'error')
                return redirect(url_for('index'))
            
            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, password, email, role, full_name, phone, location) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (username, password, email, 'user', full_name, phone, location)
            )
            
            connection.commit()
            
            # Auto-login after signup
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchone()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['logged_in'] = True
                
                print(f"DEBUG: Signup successful - User: {user['username']}")
                return redirect(url_for('user_index'))
                
        except Exception as e:
            print(f"DEBUG: Signup error - {e}")
            flash('Error creating account. Please try again.', 'error')
            return redirect(url_for('index'))
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        flash('Database connection error', 'error')
        return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user_type = request.form.get('user_type')
    
    print(f"DEBUG: Login attempt - Username: {username}, Type: {user_type}")
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(
                "SELECT * FROM users WHERE username = %s AND password = %s AND role = %s",
                (username, password, user_type)
            )
            user = cursor.fetchone()
            
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                session['logged_in'] = True
                
                print(f"DEBUG: Login successful - User: {user['username']}, Role: {user['role']}")
                
                if user_type == 'user':
                    return redirect(url_for('user_index'))
                elif user_type == 'official':
                    return redirect(url_for('official_dashboard'))
                elif user_type == 'verifier':
                    return redirect(url_for('verifier_dashboard'))
            else:
                print("DEBUG: Login failed - Invalid credentials")
                flash('Invalid username or password', 'error')
                return redirect(url_for('index'))
                
        except Exception as e:
            print(f"DEBUG: Login error - {e}")
            flash('Database error', 'error')
            return redirect(url_for('index'))
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        print("DEBUG: Login failed - Database connection error")
        flash('Database connection error', 'error')
        return redirect(url_for('index'))

# User Routes
@app.route('/user')
def user_dashboard():
    if not session.get('logged_in') or session.get('role') != 'user':
        return redirect(url_for('index'))
    return redirect(url_for('user_index'))

@app.route('/user/index')
def user_index():
    if not session.get('logged_in') or session.get('role') != 'user':
        return redirect(url_for('index'))
    return render_template('user/index.html', username=session.get('username'))

@app.route('/user/success')
def user_success():
    if not session.get('logged_in') or session.get('role') != 'user':
        return redirect(url_for('index'))
    return render_template('user/success.html', username=session.get('username'))

@app.route('/user/logout')
def user_logout():
    session.clear()
    return redirect(url_for('index'))

# Official Routes
@app.route('/official')
def official_dashboard():
    if not session.get('logged_in') or session.get('role') != 'official':
        return redirect(url_for('index'))
    return render_template('official/dashboard.html', username=session.get('username'))

@app.route('/official/analytics')
def official_analytics():
    if not session.get('logged_in') or session.get('role') != 'official':
        return redirect(url_for('index'))
    return render_template('official/analytics.html', username=session.get('username'))

# Verifier Routes
@app.route('/verifier')
def verifier_dashboard():
    if not session.get('logged_in') or session.get('role') != 'verifier':
        return redirect(url_for('index'))
    return render_template('verifier/dashboard.html', username=session.get('username'))

@app.route('/verifier/reportdetail')
def verifier_report_detail():
    if not session.get('logged_in') or session.get('role') != 'verifier':
        return redirect(url_for('index'))
    return render_template('verifier/reportdetail.html', username=session.get('username'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# API routes for password reset
@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    email = request.json.get('email')
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            if user:
                # Generate OTP
                otp = str(random.randint(100000, 999999))
                expires_at = datetime.now() + timedelta(minutes=10)
                
                # Store OTP in database
                cursor.execute(
                    "INSERT INTO password_resets (email, otp, expires_at) VALUES (%s, %s, %s)",
                    (email, otp, expires_at)
                )
                
                connection.commit()
                
                return jsonify({
                    'success': True,
                    'message': 'OTP sent to your email',
                    'otp': otp
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Email not found'
                }), 404
                
        except Exception as e:
            print(f"Error in forgot_password: {e}")
            return jsonify({
                'success': False,
                'message': 'Database error'
            }), 500
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        return jsonify({
            'success': False,
            'message': 'Database connection error'
        }), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    email = request.json.get('email')
    otp = request.json.get('otp')
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            cursor.execute(
                "SELECT * FROM password_resets WHERE email = %s AND otp = %s AND used = FALSE AND expires_at > NOW()",
                (email, otp)
            )
            reset_record = cursor.fetchone()
            
            if reset_record:
                # Mark OTP as used
                cursor.execute(
                    "UPDATE password_resets SET used = TRUE WHERE id = %s",
                    (reset_record['id'],)
                )
                connection.commit()
                
                session['reset_email'] = email
                session['otp_verified'] = True
                
                return jsonify({'success': True, 'message': 'OTP verified successfully'})
            else:
                return jsonify({'success': False, 'message': 'Invalid or expired OTP'}), 400
                
        except Exception as e:
            print(f"Error in verify_otp: {e}")
            return jsonify({'success': False, 'message': 'Database error'}), 500
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        return jsonify({'success': False, 'message': 'Database connection error'}), 500
# Add this route for user dashboard
@app.route('/user/dashboard')
def user_dashboard_page():
    if not session.get('logged_in') or session.get('role') != 'user':
        return redirect(url_for('index'))
    return render_template('user/userdashboard.html', username=session.get('username'))

# Add this route for report submission
@app.route('/submit_report', methods=['POST'])
def submit_report():
    if not session.get('logged_in') or session.get('role') != 'user':
        return redirect('/')
    
    hazard_type = request.form.get('hazard_type')
    description = request.form.get('description')
    latitude = request.form.get('latitude')
    longitude = request.form.get('longitude')
    location_text = request.form.get('location_text')
    
    print(f"DEBUG: Report submission - User: {session.get('username')}, Type: {hazard_type}")
    
    if not hazard_type or not description:
        flash('Please fill all required fields', 'error')
        return redirect('/user/index')
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor()
            
            # Insert report into database
            cursor.execute(
                "INSERT INTO reports (user_id, username, hazard_type, description, latitude, longitude, location_text) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (session['user_id'], session['username'], hazard_type, description, latitude, longitude, location_text)
            )
            
            connection.commit()
            
            print(f"DEBUG: Report submitted successfully - ID: {cursor.lastrowid}")
            # Use direct URL path instead of url_for
            return render_template('/user/success.html', username=session.get('username'))
                
        except Exception as e:
            print(f"DEBUG: Report submission error - {e}")
            flash('Error submitting report. Please try again.', 'error')
            return redirect('/user/index')
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        flash('Database connection error', 'error')
        return redirect('/user/index')
@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    email = request.json.get('email')
    new_password = request.json.get('new_password')
    
    if session.get('otp_verified') and session.get('reset_email') == email:
        connection = get_db_connection()
        if connection:
            cursor = None
            try:
                cursor = connection.cursor()
                
                cursor.execute(
                    "UPDATE users SET password = %s WHERE email = %s",
                    (new_password, email)
                )
                connection.commit()
                
                session.pop('reset_email', None)
                session.pop('otp_verified', None)
                
                return jsonify({'success': True, 'message': 'Password updated successfully'})
                
            except Exception as e:
                print(f"Error in reset_password: {e}")
                return jsonify({'success': False, 'message': 'Database error'}), 500
            finally:
                if cursor:
                    cursor.close()
                connection.close()
        else:
            return jsonify({'success': False, 'message': 'Database connection error'}), 500
    
    return jsonify({'success': False, 'message': 'Password reset failed'}), 400

if __name__ == '__main__':
    app.run(debug=True)