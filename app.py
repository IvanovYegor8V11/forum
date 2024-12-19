from flask import Flask, jsonify, make_response, render_template, redirect, url_for, flash, session, request
from config import Config
from forms import RegisterForm, LoginForm
from models import db, User, Message
import logging
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.dom.minidom import parseString

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

user_logger = logging.getLogger("user_actions")
user_logger.setLevel(logging.INFO)
user_handler = logging.FileHandler("user_actions.log")
user_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
user_logger.addHandler(user_handler)

server_logger = logging.getLogger('werkzeug')
server_logger.setLevel(logging.INFO)
server_logger.addHandler(logging.StreamHandler())

def log_user_action(action):
    username = session.get("username", "anonymous")
    if session.get("is_admin"):
        return
    user_logger.info(f"User: {username}, Action: {action}")

@app.route('/')
def index():
    log_user_action("Visited the chat page")
    return redirect(url_for('chat'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.username.data.lower() == 'admin':
            flash('Username "admin" is reserved. Please choose a different username.', 'danger')
            return redirect(url_for('register'))
        
        existing_user = User.query.filter_by(username=form.username.data).first()
        if existing_user:
            flash('Username already taken. Please choose a different one.', 'danger')
            return redirect(url_for('register'))
        
        user = User(username=form.username.data, password=form.password.data)
        db.session.add(user)
        db.session.commit()
        
        log_user_action(f"Registered a new account: {form.username.data}")
        
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_admin'] = False
        
        flash('You have successfully registered and logged in!', 'success')
        return redirect(url_for('chat'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data, password=form.password.data).first()
        if user:
            session['user_id'] = user.id
            session['username'] = user.username
            session['is_admin'] = (user.username == 'admin')
            
            log_user_action("Logged in")
            flash('Logged in successfully.', 'success')
            
            if session['is_admin']:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('chat'))
        flash('Invalid username or password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    user_logged_in = 'user_id' in session

    messages_limit = 10

    if request.method == 'POST' and user_logged_in and 'content' in request.form:
        content = request.form['content']
        
        if not content.strip():
            error_message = "Message cannot be empty."
            messages = Message.query.filter_by(visible=True).order_by(Message.id.desc()).limit(messages_limit).all()
            return render_template('chat.html', error_message=error_message, messages=messages, user_logged_in=user_logged_in)

        message = Message(content=content, user_id=session['user_id'], timestamp=datetime.now())
        db.session.add(message)
        db.session.commit()

        log_user_action("Sent a message")

    search_query = request.args.get('search')

    if search_query:
        search_terms = search_query.split()
        filters = [Message.content.ilike(f'%{term}%') for term in search_terms]
        messages = Message.query.filter(Message.visible.is_(True), *filters).order_by(Message.id.desc()).limit(messages_limit).all()
        log_user_action("Searched the message")
    else:
        messages = Message.query.filter_by(visible=True).order_by(Message.id.desc()).limit(messages_limit).all()

    show_all = 'show_all' in request.args

    if show_all:
        messages = Message.query.filter_by(visible=True).order_by(Message.id.desc()).all()

    log_user_action("Viewed the chat")
    return render_template(
        'chat.html',
        messages=messages,
        search_query=search_query,
        user_logged_in=user_logged_in,
        error_message=None,
        show_all=show_all
    )

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin_panel'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin' and password == 'admin':
            session['user_id'] = 1
            session['username'] = username
            session['is_admin'] = True
            flash('Admin logged in successfully.', 'success')
            return redirect(url_for('admin_panel'))
        else:
            flash('Invalid admin username or password.', 'danger')

    return render_template('admin_login.html')

@app.route('/admin-panel')
def admin_panel():
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    
    return render_template('admin_panel.html')

@app.route('/admin-messages', methods=['GET', 'POST'])
def admin_messages():
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        message_id = request.form.get('message_id')
        action = request.form.get('action')
        message = Message.query.get(message_id)
        
        if message:
            if action == 'toggle_visibility':
                message.visible = not message.visible
                db.session.commit()
                flash('Message visibility updated.', 'success')
            elif action == 'delete':
                db.session.delete(message)
                db.session.commit()
                flash('Message deleted.', 'success')
            elif action == 'save_edit':
                new_content = request.form.get('new_content')
                if new_content:
                    message.content = new_content
                    db.session.commit()
                    flash('Message updated.', 'success')
            return redirect(url_for('admin_messages'))
    
    messages = Message.query.order_by(Message.id.desc()).all()
    return render_template('admin_messages.html', messages=messages)

@app.route('/admin-logs', methods=['GET'])
def admin_logs():
    if not session.get('is_admin'):
        flash('Access denied.', 'danger')
        return redirect(url_for('login'))
    
    # Параметры фильтрации
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    page = int(request.args.get('page', 1))  # Номер страницы
    logs_per_page = 10  # Количество логов на страницу

    logs = []
    log_file = "user_actions.log"

    try:
        with open(log_file, 'r') as file:
            for line in file:
                parts = line.strip().split(" - ", 1)
                if len(parts) != 2:
                    continue
                
                date_time, details = parts
                if "User: " in details and ", Action: " in details:
                    user_part = details.split(", Action: ")[0]
                    action_part = details.split(", Action: ")[1]
                    username = user_part.replace("User: ", "").strip()
                    action = action_part.strip()
                else:
                    continue
                
                log_date = datetime.strptime(date_time, '%Y-%m-%d %H:%M:%S')
                
                # Фильтрация по дате
                if start_date and log_date < datetime.strptime(start_date, '%Y-%m-%d'):
                    continue
                if end_date and log_date > datetime.strptime(end_date, '%Y-%m-%d'):
                    continue
                
                logs.append({"date_time": date_time, "username": username, "action": action})
    
    except FileNotFoundError:
        flash('Log file not found.', 'danger')
        return redirect(url_for('admin_panel'))

    logs = sorted(logs, key=lambda x: x['date_time'], reverse=True)

    # Пагинация
    total_logs = len(logs)
    total_pages = (total_logs + logs_per_page - 1) // logs_per_page
    start_index = (page - 1) * logs_per_page
    end_index = start_index + logs_per_page
    logs_paginated = logs[start_index:end_index]

    return render_template(
        'admin_logs.html',
        logs=logs_paginated,
        page=page,
        total_pages=total_pages,
        start_date=start_date,
        end_date=end_date
    )


@app.route('/download-logs/<format>', methods=['GET'])
def download_logs(format):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    logs = []
    log_file = "user_actions.log"
    
    try:
        with open(log_file, 'r') as file:
            for line in file:
                parts = line.strip().split(" - ", 1)
                if len(parts) != 2:
                    continue
                
                date_time, details = parts
                if "User: " in details and ", Action: " in details:
                    user_part = details.split(", Action: ")[0]
                    action_part = details.split(", Action: ")[1]
                    username = user_part.replace("User: ", "").strip()
                    action = action_part.strip()
                else:
                    continue
                
                log_date = datetime.strptime(date_time, '%Y-%m-%d %H:%M:%S')
                
                if start_date and log_date < datetime.strptime(start_date, '%Y-%m-%d'):
                    continue
                if end_date and log_date > datetime.strptime(end_date, '%Y-%m-%d'):
                    continue
                
                logs.append({"date_time": date_time, "username": username, "action": action})
    
    except FileNotFoundError:
        return "Log file not found.", 404
    
    if format == 'txt':
        content = "\n".join([f"{log['date_time']} - {log['username']} - {log['action']}" for log in logs])
        response = make_response(content)
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = 'attachment; filename=logs.txt'
        return response
    
    elif format == 'json':
        response = make_response(jsonify(logs))
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = 'attachment; filename=logs.json'
        return response
    
    elif format == 'xml':
        root = ET.Element("logs")
        for log in logs:
            log_entry = ET.SubElement(root, "log")
            ET.SubElement(log_entry, "date_time").text = log["date_time"]
            ET.SubElement(log_entry, "username").text = log["username"]
            ET.SubElement(log_entry, "action").text = log["action"]
        
        xml_str = ET.tostring(root, encoding="unicode")
        pretty_xml = parseString(xml_str).toprettyxml(indent="  ")
        
        response = make_response(pretty_xml)
        response.headers['Content-Type'] = 'application/xml'
        response.headers['Content-Disposition'] = 'attachment; filename=logs.xml'
        return response
    
    else:
        return "Invalid format requested.", 400

@app.route('/logout')
def logout():
    username = session.get('username', 'anonymous')  # Сохраняем имя для логов перед очисткой
    log_user_action(f"Logged out")
    session.pop('user_id', None)
    session.pop('is_admin', None)
    session.pop('username', None)  # Удаляем имя пользователя из сессии
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
