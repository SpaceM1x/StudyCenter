import sqlite3
from functools import wraps
from flask import Flask, request, redirect, url_for, render_template, session, flash
from markupsafe import escape
import pyotp
import bcrypt


app = Flask(__name__)
app.secret_key = 'your_secret_key_here'


def get_db_connection():
    conn = sqlite3.connect('education_center.db')
    conn.row_factory = sqlite3.Row
    return conn


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Пожалуйста, войдите для доступа к этой странице', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Главная страница с навигационными кнопками
@app.route('/')
def index():
    return render_template('index.html')

# -------------------------------
# CRUD для преподавателей
# -------------------------------

@app.route('/teachers')
@login_required
def list_teachers():
    conn = get_db_connection()
    teachers = conn.execute('SELECT * FROM teachers').fetchall()
    conn.close()
    return render_template('teachers.html', teachers=teachers)

@app.route('/teachers/create', methods=['GET', 'POST'])
@login_required
def create_teacher():
    if request.method == 'POST':
        name = request.form['name']
        subject = request.form['subject']
        email = request.form['email']
        phone = request.form.get('phone')
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO teachers (name, subject, email, phone) VALUES (?, ?, ?, ?)',
            (name, subject, email, phone)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('list_teachers'))
    return render_template('teacher_form.html')

@app.route('/teachers/<int:teacher_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_teacher(teacher_id):
    conn = get_db_connection()
    teacher = conn.execute('SELECT * FROM teachers WHERE id = ?', (teacher_id,)).fetchone()
    if request.method == 'POST':
        name = request.form['name']
        subject = request.form['subject']
        email = request.form['email']
        phone = request.form.get('phone')
        conn.execute(
            'UPDATE teachers SET name = ?, subject = ?, email = ?, phone = ? WHERE id = ?',
            (name, subject, email, phone, teacher_id)
        )
        conn.commit()
        conn.close()
        return redirect(url_for('list_teachers'))
    conn.close()
    return render_template('teacher_form.html', teacher=teacher)

@app.route('/teachers/<int:teacher_id>/delete', methods=['POST'])
@login_required
def delete_teacher(teacher_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM teachers WHERE id = ?', (teacher_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('list_teachers'))

# -------------------------------
# CRUD для учеников
# -------------------------------

@app.route('/students')
@login_required
def list_students():
    conn = get_db_connection()
    students = conn.execute('SELECT * FROM students').fetchall()
    conn.close()
    return render_template('students.html', students=students)

@app.route('/students/create', methods=['GET', 'POST'])
@login_required
def create_student():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        conn = get_db_connection()
        conn.execute('INSERT INTO students (name, email) VALUES (?, ?)', (name, email))
        conn.commit()
        conn.close()
        return redirect(url_for('list_students'))
    return render_template('student_form.html')

@app.route('/students/<int:student_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    conn = get_db_connection()
    student = conn.execute('SELECT * FROM students WHERE id = ?', (student_id,)).fetchone()
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        conn.execute('UPDATE students SET name = ?, email = ? WHERE id = ?', (name, email, student_id))
        conn.commit()
        conn.close()
        return redirect(url_for('list_students'))
    conn.close()
    return render_template('student_form.html', student=student)

@app.route('/students/<int:student_id>/delete', methods=['POST'])
@login_required
def delete_student(student_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM students WHERE id = ?', (student_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('list_students'))

# -------------------------------
# CRUD для предметов
# -------------------------------

@app.route('/subjects')
@login_required
def list_subjects():
    conn = get_db_connection()
    subjects = conn.execute('SELECT * FROM subjects').fetchall()
    conn.close()
    return render_template('subjects.html', subjects=subjects)

@app.route('/subjects/create', methods=['GET', 'POST'])
@login_required
def create_subject():
    if request.method == 'POST':
        name = request.form['name']
        conn = get_db_connection()
        conn.execute('INSERT INTO subjects (name) VALUES (?)', (name,))
        conn.commit()
        conn.close()
        return redirect(url_for('list_subjects'))
    return render_template('subject_form.html')

@app.route('/subjects/<int:subject_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_subject(subject_id):
    conn = get_db_connection()
    subject = conn.execute('SELECT * FROM subjects WHERE id = ?', (subject_id,)).fetchone()
    if request.method == 'POST':
        name = request.form['name']
        conn.execute('UPDATE subjects SET name = ? WHERE id = ?', (name, subject_id))
        conn.commit()
        conn.close()
        return redirect(url_for('list_subjects'))
    conn.close()
    return render_template('subject_form.html', subject=subject)

@app.route('/subjects/<int:subject_id>/delete', methods=['POST'])
@login_required
def delete_subject(subject_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM subjects WHERE id = ?', (subject_id,))
    conn.commit()
    conn.close()
    return redirect(url_for('list_subjects'))


# Регистрация (исправленная версия)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Хеширование пароля с bcrypt
        hashed_password = lab5_hash_password(password)

        conn = get_db_connection()
        try:
            conn.execute(
                'INSERT INTO users (username, password, is_2fa_enabled) VALUES (?, ?, ?)',
                (username, hashed_password, False)  # 2FA по умолчанию выключена
            )
            conn.commit()
            flash('Регистрация успешна!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Имя пользователя занято', 'error')
        finally:
            conn.close()
    return render_template('register.html')


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        otp = request.form.get('otp', '')  # Поле для OTP

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode(), user['password'].encode()):
            # Если 2FA включена
            if user['is_2fa_enabled']:
                if not verify_totp_token(user['totp_secret'], otp):
                    flash('Неверный OTP', 'error')
                    return render_template('login_2fa.html')  # Шаблон для ввода OTP

            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Вход выполнен!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Ошибка входа', 'error')

    return render_template('login.html')


@app.route('/settings/2fa', methods=['GET', 'POST'])
@login_required
def manage_2fa():
    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    if request.method == 'POST':
        action = request.form['action']
        if action == 'enable':
            secret = generate_totp_secret()
            conn.execute('UPDATE users SET totp_secret = ?, is_2fa_enabled = ? WHERE id = ?',
                         (secret, True, user_id))
            flash('2FA включена. Сохраните секрет: ' + secret, 'success')
        elif action == 'disable':
            conn.execute('UPDATE users SET totp_secret = NULL, is_2fa_enabled = ? WHERE id = ?',
                         (False, user_id))
            flash('2FA отключена', 'info')
        conn.commit()
        conn.close()
        return redirect(url_for('manage_2fa'))

    conn.close()
    return render_template('2fa_settings.html', user=user)

# Уязвимая версия входа
@app.route('/vuln_login', methods=['GET', 'POST'])
def vuln_login():
    if request.method == 'POST':
        username = request.form['username']

        conn = get_db_connection()
        # Уязвимый запрос (игнорируем пароль)
        query = f"SELECT * FROM users WHERE username = '{username}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Успешный вход через уязвимость!', 'danger')
            return redirect(url_for('index'))
        else:
            flash('Неверные данные', 'error')

    return render_template('vuln_login.html')


# Лабораторная работа по XSS
@app.route('/xss_lab')
def xss_lab():
    greeting = request.args.get('greeting', None)
    safe_greeting = request.args.get('safe_greeting', None)
    csp_greeting = request.args.get('csp_greeting', None)
    return render_template('xss_lab.html',
                           greeting=greeting,
                           safe_greeting=safe_greeting,
                           csp_greeting=csp_greeting)


# Задание 1: Уязвимость Reflected XSS
@app.route('/xss_reflected')
def xss_reflected():
    name = request.args.get('name', 'Гость')
    greeting = f'<h1>Привет, {name}!</h1>'
    return redirect(url_for('xss_lab', greeting=greeting))


# Задание 3: Защита с помощью экранирования
@app.route('/xss_protected')
def xss_protected():
    name = escape(request.args.get('name', 'Гость'))
    safe_greeting = f'<h1>Привет, {name}!</h1>'
    return redirect(url_for('xss_lab', safe_greeting=safe_greeting))


# Задание 4: Защита с использованием CSP
@app.route('/xss_csp')
def xss_csp():
    name = request.args.get('name', 'Гость')

    # Преобразуем HTML-теги для отображения как текст
    display_name = name.replace('<', '&lt;').replace('>', '&gt;')

    # При этом сохраняем структуру HTML для заголовка
    greeting = f'<h1>Привет, {display_name}!</h1>'

    # Рендерим шаблон напрямую
    response = render_template('xss_lab.html',
                               greeting=None,
                               safe_greeting=None,
                               csp_greeting=greeting)

    # Добавляем заголовок CSP
    response = app.make_response(response)
    response.headers[
        'Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'none'"

    return response

# Лабораторная работа 5

@app.route('/lab5')
def lab5():
    return render_template('lab5.html')

# Реализация 2FA
def generate_totp_secret():
    return pyotp.random_base32()

def verify_totp_token(secret, token):
    return pyotp.TOTP(secret).verify(token)

# Реализация хеширования
def lab5_hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode(), salt)
    return salt.decode(), hashed.decode()

@app.route('/lab5/2fa', methods=['POST'])
def lab5_2fa():
    secret = generate_totp_secret()
    current_otp = pyotp.TOTP(secret).now()
    return render_template('lab5.html',
                         lab5_secret=secret,
                         lab5_current_otp=current_otp)

@app.route('/lab5/hash', methods=['POST'])
def lab5_hash():
    password = request.form['password']
    salt, hashed = lab5_hash_password(password)
    return render_template('lab5.html',
                         lab5_salt=salt,
                         lab5_hash=hashed)












# Выход
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'info')
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)
