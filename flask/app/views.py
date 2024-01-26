import secrets
import sqlite3
import bleach
import markdown
import time

from flask import g, render_template, request, redirect, url_for, flash, Markup
from flask_talisman import Talisman
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError, Email

from app import app
from app import helpers

Talisman(app, content_security_policy={
    'script-src': "'self' 'nonce-{nonce}'",  # Using atribute nonce
})

allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul', 'h1', 'h2', 'h3', 'h4', 'h5', 'p', 'img']
allowed_attributes = {'a': ['href', 'title'], 'img': ['src', 'alt']}

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

MAX_LOGIN_ATTEMPTS = 3
DELAY_DURATION = 5
BLOCK_THRESHOLD = 5

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, message='Username must be at least 3 characters long')])
    email = StringField('Email', validators=[DataRequired(), Email(message='Invalid email address')])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=9, message='Password must be at least 9 characters long')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Register')

    def validate_email(self, field):
        if not helpers.is_valid_email(field.data):
            raise ValidationError('Invalid email address')

    def validate_password(self, field):
        if not helpers.check_criteria(field.data):
            raise ValidationError('Password does not match criteria: 1[A-Z], 1[a-z], 1[0-9], 1[special char], >8 length')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class NoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    note_type = SelectField('Note Type', choices=[('PUBLIC', 'Public'), ('PRIVATE', 'Private'), ('PROTECTED', 'Protected')], validators=[DataRequired()])
    submit = SubmitField('Save')

class NotePasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Show')

class CreateNoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save')

class CreateProtectedNoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=9, message='Password must be at least 9 characters long')])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords must match')])
    submit = SubmitField('Save')
    
    def validate_password(self, field):
        if not helpers.check_criteria(field.data):
            raise ValidationError('Password does not match criteria: 1[A-Z], 1[a-z], 1[0-9], 1[special char], >8 length')

class EditNoteForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save')

class NoteTypeForm(FlaskForm):
    note_type = SelectField('Note Type', choices=[('PUBLIC', 'Public'), ('PRIVATE', 'Private'), ('PROTECTED', 'Protected')], validators=[DataRequired()])
    submit = SubmitField('Save')

class ShareNoteForm(FlaskForm):
    user_public_id = StringField('User Public Id', validators=[DataRequired()])
    submit = SubmitField('Save')


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['SQLITE_DATABASE'])
    return g.db


def fetch_single_note(sql):
    note_result = sql.fetchone()
    if note_result:
        note_id, title, type, password, salt, creation_date, content, owner_id, owner_name = note_result
        note = {
            'note_id': note_id,
            'title': title,
            'type': type,
            'password': password,
            'salt': salt,
            'creation_date': creation_date,
            'content': content,
            'owner_id': owner_id,
            'owner_name': owner_name
        }
        return note
    return None


# User class with UserMixin
class User(UserMixin):
    def __init__(self, user_id, name, email, password, salt, public_id):
        self.id = user_id
        self.name = name
        self.email = email
        self.password = password
        self.salt = salt
        self.public_id = public_id


# Load user function required by Flask-Login
@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    sql = db.cursor()
    sql.execute('SELECT * FROM user WHERE user_id=?', (user_id,))
    user_data = sql.fetchone()
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3], user_data[4], user_data[5])
    return None


@app.errorhandler(404)
def page_not_found(error):
    return render_template('404.html'), 404


@app.route('/', methods=['GET'])
def homepage():
    nonce = secrets.token_hex(16)
    db = get_db()
    sql = db.cursor()
    user_name = None
    public_id = None

    if not current_user.is_authenticated:
        # If the user is not logged in, show only public notes
        sql.execute("SELECT note_id, title, type, owner_name FROM note WHERE type=?", ('PUBLIC',))
        notes = [dict(zip(('note_id', 'title', 'note_type', 'owner_name'), row)) for row in sql.fetchall()]

    else:
        # If the user is logged in, show both public and user notes or shared notes
        user_id = current_user.id
        user_name = current_user.name
        public_id = current_user.public_id

        sql.execute("""
            SELECT note_id, title, type, owner_name
            FROM note
            WHERE owner_id=? OR type=?
            OR note_id IN (SELECT note_id FROM shared_note WHERE user_id=?)
        """, (user_id, 'PUBLIC', user_id))
        notes = [dict(zip(('note_id', 'title', 'note_type', 'owner_name'), row)) for row in sql.fetchall()]

    return render_template('homepage.html', notes=notes, user_name=user_name, public_id=public_id, nonce=nonce)


@app.route('/note/<string:note_id>', methods=['GET', 'POST'])
def view_note(note_id):
    nonce = secrets.token_hex(16)
    db = get_db()
    sql = db.cursor()

    is_owner = None
    edit_enable = False
    share_enable = False
    content_enable = True

    if not current_user.is_authenticated:
        sql.execute("SELECT * FROM note WHERE note_id=? AND type=?", (note_id, 'PUBLIC'))
        note = fetch_single_note(sql)
        if not note:
            flash('Note not found or you do not have permission to view it.', 'error')
            return redirect(url_for('homepage'))
        # Print raw content before rendering
        print("Raw Content Before Rendering:", note['content'])


        # Print content after rendering
        print("Content After Rendering:", note['content'])
        return render_template('view_note.html', note=note, is_owner=is_owner, 
                content_enable=content_enable, form=None, edit_enable=edit_enable, share_enable=share_enable, nonce=nonce)
    else:
        user_id = current_user.id
        sql.execute("SELECT * FROM note WHERE note_id=?", (note_id, ))
        note = fetch_single_note(sql)
        if not note:
            flash('Note not found or you do not have permission to view it.', 'error')
            return redirect(url_for('homepage'))

        if note['type'] == 'PUBLIC':
            if note['owner_id'] == user_id:
                is_owner = True
                edit_enable = True
                return render_template('view_note.html', note=note, is_owner=is_owner,
                    content_enable=content_enable, form=None, edit_enable=edit_enable, share_enable=share_enable, nonce=nonce)
            else:
                return render_template('view_note.html', note=note, is_owner=is_owner,
                    content_enable=content_enable, form=None, edit_enable=edit_enable, share_enable=share_enable, nonce=nonce)

        elif note['type'] == 'PRIVATE':
            if note['owner_id'] == user_id:
                is_owner = True
                edit_enable = True
                share_enable = True
                return render_template('view_note.html', note=note, is_owner=is_owner,
                        content_enable=content_enable, form=None, edit_enable=edit_enable, share_enable=share_enable, nonce=nonce)
            else:
                sql.execute("SELECT note_id FROM shared_note WHERE note_id=? AND user_id=?", (note_id, user_id))
                result = sql.fetchone()
                if not result:
                    flash('Note not found or you do not have permission to view it.', 'error')
                    return redirect(url_for('homepage'))
                return render_template('view_note.html', note=note, is_owner=is_owner,
                        content_enable=content_enable, form=None, edit_enable=edit_enable, share_enable=share_enable, nonce=nonce)

        elif note['type'] == 'PROTECTED':
            if note['owner_id'] == user_id:
                if request.method == 'GET':
                    content_enable = False
                    form = NotePasswordForm()
                    return render_template('view_note.html', note=note, is_owner=is_owner,
                        content_enable=content_enable, form=form, edit_enable=edit_enable, share_enable=share_enable, nonce=nonce)
                elif request.method == "POST":
                    entered_password = request.form.get('password')
                    if helpers.is_password_correct(entered_password, note['password'], note['salt']):
                        content_enable = True
                        edit_enable = True
                        is_owner = True
                        return render_template('view_note.html', note=note, is_owner=is_owner,
                            content_enable=content_enable, form=None, edit_enable=edit_enable, share_enable=share_enable, nonce=nonce)
                    else:
                        flash('Incorrect password. Please try again.', 'error')
                        return redirect(url_for('view_note', note_id=note_id))
            else:
                flash('Note not found or you do not have permission to view it.', 'error')
                return redirect(url_for('homepage'))

        else:
            flash('Note not found or you do not have permission to view it.', 'error')
            return redirect(url_for('homepage'))


@app.route('/note/<string:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit(note_id):
    nonce = secrets.token_hex(16)

    db = get_db()
    sql = db.cursor()

    sql.execute("SELECT * FROM note WHERE note_id=?", (note_id, ))
    note = fetch_single_note(sql)

    if not note or note['owner_id'] != current_user.id:
        flash('Note not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('homepage'))

    form = EditNoteForm(request.form, title=note['title'], content=note['content'])

    if form.validate_on_submit():
        new_title = form.title.data
        new_content = form.content.data
        content = bleach.linkify(bleach.clean(markdown.markdown(new_content, output_format='html'),tags=allowed_tags, attributes=allowed_attributes, strip=True))
        sql.execute("UPDATE note SET title=?, content=? WHERE note_id=?", (new_title, content, note_id))
        db.commit()

        return redirect(url_for('view_note', note_id=note_id))

    return render_template('edit.html', form=form, note=note, nonce=nonce)

@app.route('/create_note', methods=['GET', 'POST'])
@login_required
def create_note():
    form = NoteTypeForm()
    if form.validate_on_submit():
        note_type = form.note_type.data
        return redirect(url_for('create_note_with_type', note_type=note_type))
    return render_template('choose_note_type.html', form=form)
    
@app.route('/create_note/<note_type>', methods=['GET', 'POST'])
@login_required
def create_note_with_type(note_type):
    nonce = secrets.token_hex(16)
    db = get_db()
    sql = db.cursor()

    if note_type == 'PROTECTED':
        form = CreateProtectedNoteForm()
        if form.validate_on_submit():
            title = bleach.clean(form.title.data, tags=[], strip=True)
            con = form.content.data
            password = form.password.data
            content = bleach.linkify(bleach.clean(markdown.markdown(con, output_format='html'),tags=allowed_tags, attributes=allowed_attributes, strip=True))
            hash_pass, salt = helpers.hash_password(password)
            note_id = helpers.generate_gguid()
            sql.execute("""
                INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
                VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
            """, (note_id, title, note_type, hash_pass, salt, content, current_user.name, current_user.name))
            db.commit()
            return redirect(url_for('homepage'))
        return render_template(f'create_protected_note.html', form=form, note_type=note_type, nonce=nonce)

    else:
        form = CreateNoteForm()
        if form.validate_on_submit():
            title = bleach.clean(form.title.data, tags=[], strip=True)
            con = form.content.data
            print(con)
            content = bleach.linkify(bleach.clean(markdown.markdown(con, output_format='html'),tags=allowed_tags, attributes=allowed_attributes, strip=True))
            print(content)
            note_id = helpers.generate_gguid()
            sql.execute("""
                INSERT INTO note (note_id, title, type, password, salt, content, owner_id, owner_name)
                VALUES (?, ?, ?, ?, ?, ?, (SELECT user_id FROM user WHERE name=?), ?)
            """, (note_id, title, note_type, None, None, content, current_user.name, current_user.name))
            db.commit()
            return redirect(url_for('homepage'))
        return render_template(f'create_note.html', form=form, note_type=note_type, nonce=nonce)





@app.route('/note/<string:note_id>/delete')
@login_required
def delete(note_id):
    db = get_db()
    sql = db.cursor()

    sql.execute("SELECT * FROM note WHERE note_id=?", (note_id, ))
    note = fetch_single_note(sql)

    if not note or note['owner_id'] != current_user.id:
        flash('Note not found or you do not have permission to delete it.', 'error')
        return redirect(url_for('homepage'))

    sql.execute("DELETE FROM shared_note WHERE note_id=?", (note_id,))
    sql.execute("DELETE FROM note WHERE note_id=?", (note_id,))
    db.commit()

    return redirect(url_for('homepage'))


@app.route('/note/<string:note_id>/share', methods=['GET','POST'])
@login_required
def share(note_id):
    nonce = secrets.token_hex(16)
    db = get_db()
    sql = db.cursor()

    sql.execute("SELECT * FROM note WHERE note_id=?", (note_id, ))
    note = fetch_single_note(sql)

    if not note or note['owner_id'] != current_user.id or note['type'] != 'PRIVATE':
        flash('Note not found or you do not have permission to share it.', 'error')
        return redirect(url_for('homepage'))

    sql.execute('''
        SELECT user.name
        FROM user
        JOIN shared_note ON user.user_id = shared_note.user_id
        WHERE shared_note.note_id = ? AND user.user_id != ?
    ''', (note_id, current_user.id))
    result = sql.fetchall()

    user_names = [row[0] for row in result]
    form = ShareNoteForm()

    if form.validate_on_submit():
        user_public_id = form.user_public_id.data
        sql.execute("SELECT user_id FROM user WHERE public_id=?", (user_public_id, ))
        found_user_id = sql.fetchone()
        if found_user_id and found_user_id[0] != current_user.id:
            sql.execute("INSERT INTO shared_note (note_id, user_id) VALUES (?, ?)", (note_id, found_user_id[0]))
            db.commit()
            return redirect(url_for('view_note', note_id=note_id))
        flash('User not found.', 'error')
        return redirect(url_for('view_note', note_id=note_id))
    return render_template('share.html', form=form, note=note, nonce=nonce, shared_users=user_names)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        #time.sleep(1000)
        username = form.username.data
        email = form.email.data
        password = form.password.data

        db = get_db()
        sql = db.cursor()
        sql.execute('SELECT * FROM user WHERE name=?', (username,))
        existing_username = sql.fetchone()
        sql.execute('SELECT * FROM user WHERE email=?', (email,))
        existing_email = sql.fetchone()

        if existing_username:
            flash('User with that name already exist.', 'error')
        elif existing_email:
            flash('User with that email already exist.', 'error')
        elif not helpers.evaluate_password_strength(password):
            flash('Password too weak...', 'error')
        else:
            # Hash the password before storing it in the database
            hashed_password, salt = helpers.hash_password(password)
            user_id = helpers.generate_gguid()
            public_id = helpers.generate_gguid()
            sql.execute('INSERT INTO user (user_id, name, email, password, salt, public_id) VALUES (?, ?, ?, ?, ?, ?)',
                        (user_id, username, email, hashed_password, salt, public_id))
            db.commit()

            flash('Registration successful. You can now login.', 'success')

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        #time.sleep(1000)
        username = form.username.data
        password = form.password.data

        # Check if the username exists (name or email)
        db = get_db()
        sql = db.cursor()
        sql.execute('SELECT * FROM user WHERE name=?', (username,))
        user_data = sql.fetchone()
        if not user_data:
            sql.execute('SELECT * FROM user WHERE email=?', (username,))
            user_data = sql.fetchone()
        if user_data and helpers.is_password_correct(password, user_data[3], user_data[4]):
            # If the username and password are correct, create a session
            user_obj = User(user_data[0], user_data[1], user_data[2], user_data[3], user_data[4], user_data[5])
            login_user(user_obj)
            return redirect(url_for('homepage'))
        else:
            flash('Invalid username or password. Please try again.', 'error')


    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('homepage'))

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.before_first_request
def init_database():
    db = get_db()
    sql = db.cursor()
    helpers.initial_insert(sql)
    db.commit()
