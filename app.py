from flask import Flask, render_template, request, redirect, url_for, flash,make_response, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from functools import wraps  # Added for decorator fixes
import csv
from io import StringIO
import psycopg2  # Required for PostgreSQL on Render
from dotenv import load_dotenv  # For local environment variables
import gunicorn  # For production WSGI server (required in requirements.txt)

app = Flask(__name__,template_folder='templates')
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    tasks = db.relationship('Task', backref='user', lazy=True)

class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False, default=datetime.utcnow)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='Pending')
    hours = db.Column(db.Float, default=0.0)
    progress = db.Column(db.Integer, default=0)

# Create tables
with app.app_context():
    db.create_all()

# Authentication Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        if User.query.get(session['user_id']).is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = user.is_admin
            flash('Login successful!', 'success')
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = generate_password_hash(password)  # Fixed this line
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    current_date = datetime.now()
    
    # User's recent tasks
    user_tasks = Task.query.filter_by(user_id=user.id).order_by(Task.date.desc()).limit(10).all()
    
    # All team tasks (recent first)
    all_tasks = Task.query.order_by(Task.date.desc()).limit(20).all()
    
    # Calculate user's weekly stats
    weekly_tasks = Task.query.filter(
        Task.user_id == user.id,
        Task.date >= datetime.utcnow().date() - timedelta(days=7)
    ).all()
    
    total_hours = sum(task.hours for task in weekly_tasks) if weekly_tasks else 0
    avg_progress = sum(task.progress for task in weekly_tasks) / len(weekly_tasks) if weekly_tasks else 0
    completed_tasks = sum(1 for task in weekly_tasks if task.status == 'Completed')
    
    # Calculate team stats for all users
    users = User.query.all()
    user_stats = []
    for team_user in users:
        user_tasks = Task.query.filter_by(user_id=team_user.id).all()
        
        if user_tasks:
            user_total_hours = sum(task.hours for task in user_tasks)
            user_avg_progress = sum(task.progress for task in user_tasks) / len(user_tasks)
            user_completed_tasks = sum(1 for task in user_tasks if task.status == 'Completed')
        else:
            user_total_hours = 0
            user_avg_progress = 0
            user_completed_tasks = 0
            
        user_stats.append({
            'user': team_user,
            'total_hours': user_total_hours,
            'avg_progress': user_avg_progress,
            'completed_tasks': user_completed_tasks,
            'total_tasks': len(user_tasks)
        })
    
    return render_template('dashboard.html', 
                         user=user,
                         user_tasks=user_tasks,
                         all_tasks=all_tasks,
                         date=current_date,
                         total_hours=total_hours,
                         avg_progress=avg_progress,
                         completed_tasks=completed_tasks,
                         user_stats=user_stats)

@app.route('/task/edit/<int:task_id>', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    task = Task.query.get_or_404(task_id)
    user = User.query.get(session['user_id'])
    
    # Check if user owns the task or is admin
    if task.user_id != user.id and not user.is_admin:
        flash('You do not have permission to edit this task.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        task.description = request.form['description']
        task.hours = float(request.form['hours'])
        task.progress = int(request.form['progress'])
        task.status = 'Completed' if task.progress == 100 else 'In Progress'
        db.session.commit()
        flash('Task updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('edit_task.html', task=task)

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        description = request.form['description']
        hours = float(request.form['hours'])
        progress = int(request.form['progress'])
        
        new_task = Task(
            user_id=session['user_id'],
            description=description,
            hours=hours,
            progress=progress,
            status='Completed' if progress == 100 else 'In Progress'
        )
        db.session.add(new_task)
        db.session.commit()
        
        flash('Task reported successfully!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('report.html')

@app.route('/progress')
@login_required
def progress():
    user = User.query.get(session['user_id'])
    tasks = Task.query.filter_by(user_id=user.id).order_by(Task.date.desc()).all()
    
    # Calculate weekly progress
    weekly_tasks = Task.query.filter(
        Task.user_id == user.id,
        Task.date >= datetime.utcnow().date() - timedelta(days=7)
    ).all()
    
    total_hours = sum(task.hours for task in weekly_tasks) if weekly_tasks else 0
    avg_progress = sum(task.progress for task in weekly_tasks) / len(weekly_tasks) if weekly_tasks else 0
    
    return render_template('progress.html', 
                         tasks=tasks, 
                         total_hours=total_hours, 
                         avg_progress=avg_progress)

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    users = User.query.order_by(User.id.desc()).limit(5).all()
    tasks = Task.query.order_by(Task.date.desc()).limit(10).all()
    
    # Calculate stats
    total_users = User.query.count()
    total_tasks = Task.query.count()
    completed_tasks = Task.query.filter_by(status='Completed').count()
    
    # For charts - you'll need to implement these queries
    # weekly_data = get_weekly_task_data()  
    # pending_tasks = Task.query.filter_by(status='Pending').count()
    
    return render_template('admin/dashboard.html', 
                         users=users, 
                         tasks=tasks,
                         total_users=total_users,
                         total_tasks=total_tasks,
                         completed_tasks=completed_tasks)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin/users.html', users=users)
@app.route('/admin/progress')
@admin_required
def admin_progress():
    # Get all users and their tasks
    users = User.query.all()
    
    # Calculate stats for each user
    user_stats = []
    for user in users:
        tasks = Task.query.filter_by(user_id=user.id).all()
        
        if tasks:
            total_hours = sum(task.hours for task in tasks)
            avg_progress = sum(task.progress for task in tasks) / len(tasks)
            completed_tasks = sum(1 for task in tasks if task.status == 'Completed')
        else:
            total_hours = 0
            avg_progress = 0
            completed_tasks = 0
            
        user_stats.append({
            'user': user,
            'total_hours': total_hours,
            'avg_progress': avg_progress,
            'completed_tasks': completed_tasks,
            'total_tasks': len(tasks)
        })
    
    # Calculate overall stats
    all_tasks = Task.query.all()
    overall_stats = {
        'total_hours': sum(task.hours for task in all_tasks) if all_tasks else 0,
        'avg_progress': sum(task.progress for task in all_tasks) / len(all_tasks) if all_tasks else 0,
        'completed_tasks': sum(1 for task in all_tasks if task.status == 'Completed'),
        'total_tasks': len(all_tasks)
    }
    
    return render_template('admin/progress.html', 
                         user_stats=user_stats,
                         overall_stats=overall_stats)

@app.route('/admin/export-data')
@admin_required
def export_data():
    # Create a string buffer to hold CSV data
    csv_buffer = StringIO()
    csv_writer = csv.writer(csv_buffer)
    
    # Write header row
    csv_writer.writerow([
        'Username', 'Email', 'Task Date', 'Description', 
        'Hours', 'Progress', 'Status'
    ])
    
    # Query all tasks with user information
    tasks = Task.query.join(User).order_by(User.username, Task.date).all()
    
    # Write data rows
    for task in tasks:
        csv_writer.writerow([
            task.user.username,
            task.user.email,
            task.date.strftime('%Y-%m-%d'),
            task.description,
            task.hours,
            task.progress,
            task.status
        ])
    
    # Create response with CSV data
    response = make_response(csv_buffer.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=progress_data.csv'
    response.headers['Content-type'] = 'text/csv'
    return response


@app.route('/user/edit/<int:user_id>', methods=['POST'])
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent editing the current admin user's admin status
    if user.id == session.get('user_id'):
        flash('You cannot modify your own admin status', 'warning')
        return redirect(url_for('admin_users'))
    
    user.username = request.form['username']
    user.email = request.form['email']
    user.is_admin = 'is_admin' in request.form
    
    try:
        db.session.commit()
        flash('User updated successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error updating user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/user/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Prevent deleting the current user
    if user.id == session.get('user_id'):
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        # First delete all tasks associated with the user
        Task.query.filter_by(user_id=user.id).delete()
        # Then delete the user
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')
    
    return redirect(url_for('admin_users'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# At the bottom of your file, modify the __main__ block:
if __name__ == '__main__':
    # Only for development
    if os.environ.get('RENDER') is None:
        app.run(debug=True)
    else:
        # For production on Render
        app.run(host='0.0.0.0', port=10000, debug=False)
