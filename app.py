from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import mysql.connector
import os
from datetime import datetime, timedelta
import random

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_strong_secret_key_here')

# MySQL Database Configuration
db_config = {
    'host': os.environ.get('MYSQL_HOST', 'localhost'),
    'user': os.environ.get('MYSQL_USER', 'root'),
    'password': os.environ.get('MYSQL_PASSWORD', 'root'),
    'database': os.environ.get('MYSQL_DATABASE', 'ocean_hazards_db'),
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

'''@app.route('/login', methods=['POST'])
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
'''
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
            
            if user_type == 'verifier':
                # Check verifier credentials in verifiers table
                cursor.execute(
                    "SELECT * FROM verifiers WHERE username = %s AND password = %s AND is_active = TRUE",
                    (username, password)
                )
                user = cursor.fetchone()
            elif user_type == 'official':
                # FIRST check officials table
                cursor.execute(
                    "SELECT * FROM officials WHERE username = %s AND password = %s AND is_active = TRUE",
                    (username, password)
                )
                user = cursor.fetchone()
                
                # If not found in officials table, check users table as fallback
                if not user:
                    cursor.execute(
                        "SELECT * FROM users WHERE username = %s AND password = %s AND role = 'official'",
                        (username, password)
                    )
                    user = cursor.fetchone()
            else:
                # Check user credentials in users table
                cursor.execute(
                    "SELECT * FROM users WHERE username = %s AND password = %s AND role = %s",
                    (username, password, user_type)
                )
                user = cursor.fetchone()
            
            if user:
                if user_type == 'verifier':
                    # Set verifier session variables
                    session['verifier_id'] = user['id']
                    session['verifier_username'] = user['username']
                    session['verifier_name'] = user.get('full_name', user['username'])
                    session['verifier_logged_in'] = True
                    session['role'] = 'verifier'
                    
                    print(f"DEBUG: Verifier login successful - {user['username']}")
                    return redirect('/verifier/dashboard')
                elif user_type == 'official':
                    # Set official session variables
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = 'official'
                    session['logged_in'] = True
                    session['official_name'] = user.get('full_name', user['username'])
                    
                    print(f"DEBUG: Official login successful - {user['username']}")
                    return redirect('/official')
                else:
                    # Set regular user session variables
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    session['logged_in'] = True
                    
                    print(f"DEBUG: Login successful - User: {user['username']}, Role: {user['role']}")
                    
                    if user_type == 'user':
                        return redirect('/user/index')
            else:
                print(f"DEBUG: Login failed - Invalid credentials for {user_type}")
                flash('Invalid username or password', 'error')
                return redirect('/')
                
        except Exception as e:
            print(f"DEBUG: Login error - {e}")
            flash('Database error', 'error')
            return redirect('/')
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        print("DEBUG: Login failed - Database connection error")
        flash('Database connection error', 'error')
        return redirect('/')
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


#Verifier Routes
from datetime import datetime

# Template filters
@app.template_filter('get_priority_level')
def get_priority_level(hazard_type):
    if hazard_type in ['coastal_flooding', 'high_waves']:
        return 'high'
    elif hazard_type == 'beach_erosion':
        return 'medium'
    else:
        return 'low'

@app.template_filter('get_icon')
def get_icon(hazard_type):
    icons = {
        "coastal_flooding": "water",
        "marine_debris": "trash",
        "beach_erosion": "mountain",
        "high_waves": "wave-square",
        "unusual_tides": "tint",
        "other": "exclamation-triangle"
    }
    return icons.get(hazard_type, "exclamation-triangle")

@app.template_filter('format_hazard_type')
def format_hazard_type(hazard_type):
    return hazard_type.replace('_', ' ').title()

@app.template_filter('format_time_ago')
def format_time_ago(timestamp):
    if not timestamp:
        return 'Unknown time'
    
    now = datetime.now()
    diff = now - timestamp
    
    if diff.days > 0:
        return f"{diff.days} days ago"
    elif diff.seconds // 3600 > 0:
        return f"{diff.seconds // 3600} hours ago"
    elif diff.seconds // 60 > 0:
        return f"{diff.seconds // 60} minutes ago"
    else:
        return 'Just now'
@app.route('/verifier/dashboard')
def verifier_dashboard():
    if not session.get('verifier_logged_in'):
        print(f"DEBUG: Verifier access denied - verifier_logged_in: {session.get('verifier_logged_in')}")
        return redirect('/')
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get pending reports count from REPORTS table
            cursor.execute("SELECT COUNT(*) as count FROM reports WHERE status = 'pending'")
            pending_count_result = cursor.fetchone()
            pending_count = pending_count_result['count'] if pending_count_result else 0
            print(f"DEBUG: Pending reports count: {pending_count}")
            
            # Get approved today count from FINALREPORTS table
            today = datetime.now().date()
            cursor.execute("SELECT COUNT(*) as count FROM final_reports WHERE verifier_status = 'approved' AND DATE(verified_at) = %s", (today,))
            approved_today_result = cursor.fetchone()
            approved_today = approved_today_result['count'] if approved_today_result else 0
            print(f"DEBUG: Approved today: {approved_today}")
            
            # Get all pending reports from REPORTS table for verification
            cursor.execute("""
                SELECT r.*, u.full_name as user_full_name 
                FROM reports r 
                LEFT JOIN users u ON r.user_id = u.id 
                WHERE r.status = 'pending' 
                ORDER BY 
                    CASE 
                        WHEN r.hazard_type IN ('coastal_flooding', 'high_waves') THEN 1
                        WHEN r.hazard_type = 'beach_erosion' THEN 2
                        ELSE 3
                    END,
                    r.submitted_at DESC
            """)
            pending_reports = cursor.fetchall()
            print(f"DEBUG: Found {len(pending_reports)} pending reports")
            for report in pending_reports:
                print(f"DEBUG: Report ID: {report['id']}, Type: {report['hazard_type']}, Status: {report.get('status', 'N/A')}")
            
            # Get recent reports (last 24 hours) from REPORTS table
            yesterday = datetime.now() - timedelta(hours=24)
            cursor.execute("""
                SELECT r.*, u.full_name as user_full_name 
                FROM reports r 
                LEFT JOIN users u ON r.user_id = u.id 
                WHERE r.submitted_at >= %s 
                ORDER BY r.submitted_at DESC 
                LIMIT 10
            """, (yesterday,))
            recent_reports = cursor.fetchall()
            print(f"DEBUG: Found {len(recent_reports)} recent reports")
            
            return render_template('verifier/dashboard.html', 
                                verifier_name=session.get('verifier_name'),
                                pending_count=pending_count,
                                approved_today=approved_today,
                                pending_reports=pending_reports,
                                recent_reports=recent_reports)
                
        except Exception as e:
            print(f"DEBUG: Verifier dashboard error - {e}")
            flash('Error loading verifier dashboard', 'error')
            return render_template('verifier/dashboard.html', 
                                verifier_name=session.get('verifier_name'),
                                pending_count=0,
                                approved_today=0,
                                pending_reports=[],
                                recent_reports=[])
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        flash('Database connection error', 'error')
        return render_template('verifier/dashboard.html', 
                            verifier_name=session.get('verifier_name'),
                            pending_count=0,
                            approved_today=0,
                            pending_reports=[],
                            recent_reports=[])
@app.route('/verifier/verify_report/<int:report_id>', methods=['GET'])
def verify_report_page(report_id):
    if not session.get('verifier_logged_in'):
        print(f"DEBUG: Verifier not logged in for report {report_id}")
        return redirect('/')
    
    print(f"DEBUG: Loading verification page for report {report_id}")
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get the report details
            cursor.execute("""
                SELECT r.*, u.full_name as user_full_name, u.email as user_email 
                FROM reports r 
                LEFT JOIN users u ON r.user_id = u.id 
                WHERE r.id = %s
            """, (report_id,))
            report = cursor.fetchone()
            
            print(f"DEBUG: Query executed for report {report_id}")
            print(f"DEBUG: Report found: {report is not None}")
            
            if not report:
                print(f"DEBUG: Report {report_id} not found in database")
                flash('Report not found', 'error')
                return redirect('/verifier/dashboard')
            
            print(f"DEBUG: Successfully loaded report {report_id}: {report['hazard_type']} by {report.get('user_full_name', 'Unknown')}")
            
            return render_template('verifier/verify_report.html', 
                                report=report,
                                verifier_name=session.get('verifier_name'))
                
        except Exception as e:
            print(f"DEBUG: Get report error - {e}")
            import traceback
            print(f"DEBUG: Full traceback: {traceback.format_exc()}")
            flash('Error loading report', 'error')
            return redirect('/verifier/dashboard')
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        print("DEBUG: Database connection failed")
        flash('Database connection error', 'error')
        return redirect('/verifier/dashboard')

@app.route('/verifier/submit_verification/<int:report_id>', methods=['POST'])
def submit_verification(report_id):
    if not session.get('verifier_logged_in'):
        return redirect('/')
    
    verification_status = request.form.get('verification_status')
    comments = request.form.get('comments', '')
    
    print(f"DEBUG: Verifier action - Report: {report_id}, Status: {verification_status}, Verifier: {session.get('verifier_username')}")
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get the report data from REPORTS table
            cursor.execute("SELECT * FROM reports WHERE id = %s", (report_id,))
            report_data = cursor.fetchone()
            
            if not report_data:
                flash('Report not found', 'error')
                return redirect('/verifier/dashboard')
            
            # Map action to final status
            status_mapping = {
                'confident': 'approved',
                'likely': 'approved', 
                'unsure': 'under_review',
                'doubtful': 'rejected',
                'fake': 'rejected',
                'needs_evidence': 'under_review',
                'escalate': 'under_review'  # escalated goes to under_review for senior review
            }
            
            final_status = status_mapping.get(verification_status, 'under_review')
            
            # Insert into FINALREPORTS table with verification status
            cursor.execute("""
                INSERT INTO final_reports 
                (user_id, username, hazard_type, description, latitude, longitude, location_text, 
                 status, verifier_status, verifier_comments, verified_by, verified_at, submitted_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
            """, (
                report_data['user_id'], report_data['username'], report_data['hazard_type'], 
                report_data['description'], report_data['latitude'], report_data['longitude'], 
                report_data['location_text'], 'verified', final_status, comments, 
                session.get('verifier_username'), report_data['submitted_at']
            ))
            
            # Update the report status in REPORTS table to 'verified'
            cursor.execute("UPDATE reports SET status = 'verified', verified_at = NOW(), verifier_id = %s WHERE id = %s", 
                         (session.get('verifier_id'), report_id))
            
            connection.commit()
            
            flash(f'Report successfully verified and marked as {final_status}', 'success')
            print(f"DEBUG: Report {report_id} verified by {session.get('verifier_username')} and moved to finalreports")
            return redirect('/verifier/dashboard')
                
        except Exception as e:
            print(f"DEBUG: Verify report error - {e}")
            flash('Error processing verification', 'error')
            return redirect(f'/verifier/verify_report/{report_id}')
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        flash('Database connection error', 'error')
        return redirect('/verifier/dashboard')
@app.route('/verifier/logout')
def verifier_logout():
    session.pop('verifier_id', None)
    session.pop('verifier_username', None)
    session.pop('verifier_name', None)
    session.pop('verifier_logged_in', None)
    session.pop('role', None)
    return redirect('/')
#official 



# Official Routes
@app.route('/official')
def official_dashboard():
    if not session.get('logged_in') or session.get('role') != 'official':
        return redirect('/')
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get stats for official dashboard
            cursor.execute("SELECT COUNT(*) as count FROM reports WHERE status = 'pending'")
            pending_reports = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM finalreports WHERE verifier_status = 'approved'")
            verified_reports = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM finalreports WHERE verifier_status = 'approved' AND DATE(verified_at) = CURDATE()")
            approved_today = cursor.fetchone()['count']
            
            # Get recent verified reports
            cursor.execute("""
                SELECT fr.*, u.full_name as user_full_name 
                FROM finalreports fr 
                LEFT JOIN users u ON fr.user_id = u.id 
                WHERE fr.verifier_status = 'approved'
                ORDER BY fr.verified_at DESC 
                LIMIT 5
            """)
            recent_verified = cursor.fetchall()
            
            # Get hazard distribution data
            cursor.execute("""
                SELECT hazard_type, COUNT(*) as count 
                FROM finalreports 
                WHERE verifier_status = 'approved' 
                GROUP BY hazard_type
            """)
            hazard_distribution = cursor.fetchall()
            
            # Get reports timeline data (last 7 days)
            cursor.execute("""
                SELECT DATE(verified_at) as date, COUNT(*) as count 
                FROM finalreports 
                WHERE verifier_status = 'approved' AND verified_at >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
                GROUP BY DATE(verified_at)
                ORDER BY date
            """)
            timeline_data = cursor.fetchall()
            
            return render_template('official/official.html', 
                                username=session.get('username'),
                                pending_reports=pending_reports,
                                verified_reports=verified_reports,
                                approved_today=approved_today,
                                recent_verified=recent_verified,
                                hazard_distribution=hazard_distribution,
                                timeline_data=timeline_data)
                
        except Exception as e:
            print(f"DEBUG: Official dashboard error - {e}")
            flash('Error loading official dashboard', 'error')
            return render_template('official/official.html', 
                                username=session.get('username'),
                                pending_reports=0,
                                verified_reports=0,
                                approved_today=0,
                                recent_verified=[],
                                hazard_distribution=[],
                                timeline_data=[])
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        flash('Database connection error', 'error')
        return render_template('official/official.html', 
                            username=session.get('username'),
                            pending_reports=0,
                            verified_reports=0,
                            approved_today=0,
                            recent_verified=[],
                            hazard_distribution=[],
                            timeline_data=[])

@app.route('/official/analytics')
def official_analytics():
    if not session.get('logged_in') or session.get('role') != 'official':
        return redirect('/')
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get comprehensive analytics data
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_reports,
                    COUNT(CASE WHEN verifier_status = 'approved' THEN 1 END) as approved_reports,
                    COUNT(CASE WHEN verifier_status = 'rejected' THEN 1 END) as rejected_reports,
                    COUNT(CASE WHEN verifier_status = 'under_review' THEN 1 END) as under_review
                FROM finalreports
            """)
            analytics_summary = cursor.fetchone()
            
            # Get hazard type distribution
            cursor.execute("""
                SELECT hazard_type, COUNT(*) as count 
                FROM finalreports 
                GROUP BY hazard_type 
                ORDER BY count DESC
            """)
            hazard_analytics = cursor.fetchall()
            
            # Get monthly trend data
            cursor.execute("""
                SELECT 
                    DATE_FORMAT(verified_at, '%Y-%m') as month,
                    COUNT(*) as count
                FROM finalreports 
                WHERE verified_at >= DATE_SUB(CURDATE(), INTERVAL 12 MONTH)
                GROUP BY DATE_FORMAT(verified_at, '%Y-%m')
                ORDER BY month
            """)
            monthly_trends = cursor.fetchall()
            
            # Get top locations
            cursor.execute("""
                SELECT location_text, COUNT(*) as count 
                FROM finalreports 
                WHERE location_text IS NOT NULL 
                GROUP BY location_text 
                ORDER BY count DESC 
                LIMIT 10
            """)
            top_locations = cursor.fetchall()
            
            return render_template('official/analytics.html',
                                username=session.get('username'),
                                analytics_summary=analytics_summary,
                                hazard_analytics=hazard_analytics,
                                monthly_trends=monthly_trends,
                                top_locations=top_locations)
                
        except Exception as e:
            print(f"DEBUG: Official analytics error - {e}")
            flash('Error loading analytics', 'error')
            return render_template('official/analytics.html',
                                username=session.get('username'),
                                analytics_summary={},
                                hazard_analytics=[],
                                monthly_trends=[],
                                top_locations=[])
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        flash('Database connection error', 'error')
        return render_template('official/analytics.html',
                            username=session.get('username'),
                            analytics_summary={},
                            hazard_analytics=[],
                            monthly_trends=[],
                            top_locations=[])

# API endpoints for official dashboard
@app.route('/api/official/stats')
def official_stats():
    if not session.get('logged_in') or session.get('role') != 'official':
        return jsonify({'error': 'Unauthorized'}), 401
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Real-time stats
            cursor.execute("SELECT COUNT(*) as count FROM reports WHERE status = 'pending'")
            pending_reports = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM finalreports WHERE verifier_status = 'approved'")
            total_verified = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM finalreports WHERE DATE(verified_at) = CURDATE()")
            verified_today = cursor.fetchone()['count']
            
            cursor.execute("SELECT COUNT(*) as count FROM finalreports WHERE verifier_status = 'under_review'")
            under_review = cursor.fetchone()['count']
            
            return jsonify({
                'success': True,
                'stats': {
                    'pending_reports': pending_reports,
                    'total_verified': total_verified,
                    'verified_today': verified_today,
                    'under_review': under_review
                }
            })
                
        except Exception as e:
            print(f"DEBUG: Official stats API error - {e}")
            return jsonify({'success': False, 'error': 'Database error'}), 500
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        return jsonify({'success': False, 'error': 'Database connection error'}), 500

@app.route('/api/official/hazard-data')
def official_hazard_data():
    if not session.get('logged_in') or session.get('role') != 'official':
        return jsonify({'error': 'Unauthorized'}), 401
    
    connection = get_db_connection()
    if connection:
        cursor = None
        try:
            cursor = connection.cursor(dictionary=True)
            
            # Get hazard data for map
            cursor.execute("""
                SELECT 
                    latitude, 
                    longitude, 
                    hazard_type,
                    location_text,
                    verified_at,
                    CASE 
                        WHEN hazard_type IN ('coastal_flooding', 'high_waves') THEN 'high'
                        WHEN hazard_type = 'beach_erosion' THEN 'medium'
                        ELSE 'low'
                    END as risk_level
                FROM finalreports 
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                AND verifier_status = 'approved'
                ORDER BY verified_at DESC
                LIMIT 50
            """)
            hazard_data = cursor.fetchall()
            
            return jsonify({
                'success': True,
                'hazards': hazard_data
            })
                
        except Exception as e:
            print(f"DEBUG: Official hazard data API error - {e}")
            return jsonify({'success': False, 'error': 'Database error'}), 500
        finally:
            if cursor:
                cursor.close()
            connection.close()
    else:
        return jsonify({'success': False, 'error': 'Database connection error'}), 500

# Update your existing official routes to match
@app.route('/official/dashboard')
def official_dashboard_page():
    return redirect('/official')

@app.route('/official/logout')
def official_logout():
    session.clear()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=False)