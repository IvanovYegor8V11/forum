from flask import Flask, render_template, redirect, url_for, flash, session, request
from config import Config
from forms import RegisterForm, LoginForm
from models import db, User, Message

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

with app.app_context():
    db.create_all()

@app.template_filter('nl2br')
def nl2br_filter(text):
    return text.replace('\n', '<br>')

@app.route('/')
def index():
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
        
        flash('You have successfully registered!', 'success')
        return redirect(url_for('login'))
    
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
    
    if request.method == 'POST' and user_logged_in and 'content' in request.form:
        content = request.form['content']
        
        if not content.strip():
            error_message = "Message cannot be empty."
            
            messages = Message.query.filter_by(visible=True).order_by(Message.id.desc()).all()
            return render_template('chat.html', error_message=error_message, messages=messages, user_logged_in=user_logged_in)

        message = Message(content=content, user_id=session['user_id'])
        db.session.add(message)
        db.session.commit()
    
    search_query = request.args.get('search')
    
    if search_query:
        search_terms = search_query.split()
        
        filters = [Message.content.ilike(f'%{term}%') for term in search_terms]
    
        messages = Message.query.filter(
            Message.visible.is_(True),
            *filters
        ).order_by(Message.id.desc()).all()
    else:
        messages = Message.query.filter_by(visible=True).order_by(Message.id.desc()).all()
    
    return render_template(
        'chat.html',
        messages=messages,
        search_query=search_query,
        user_logged_in=user_logged_in,
        error_message=None
    )

@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if session.get('is_admin'):
        return redirect(url_for('admin'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == 'admin' and password == 'admin':
            session['user_id'] = 1
            session['username'] = username
            session['is_admin'] = True
            return redirect(url_for('admin'))
        else:
            flash('Invalid admin username or password.', 'danger')
            return render_template('admin_login.html')

    return render_template('admin_login.html')


@app.route('/admin', methods=['GET', 'POST'])
def admin():
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
            return redirect(url_for('admin'))
    
    messages = Message.query.order_by(Message.id.desc()).all()
    return render_template('admin.html', messages=messages)



@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('is_admin', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
