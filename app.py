from flask import Flask, request, redirect, url_for, render_template, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps  # Добавлен недостающий импорт

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Обязательно добавьте секретный ключ

# Функция для получения соединения с базой данных
def get_db_connection():
    conn = sqlite3.connect('education_center.db')
    conn.row_factory = sqlite3.Row  # Позволяет обращаться к столбцам по именам
    return conn

# Защита маршрутов (исправленная версия)
def login_required(f):
    @wraps(f)  # Теперь работает, так как импортирован from functools
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

        conn = get_db_connection()
        try:
            # Исправлена синтаксическая ошибка с закрывающими скобками
            conn.execute(
                'INSERT INTO users (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )  # Добавлена закрывающая скобка
            conn.commit()
            flash('Регистрация успешна! Теперь войдите.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Это имя пользователя уже занято', 'error')
        finally:
            conn.close()

    return render_template('register.html')


# Вход
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')

    return render_template('login.html')

# Уязвимая версия входа
@app.route('/vuln_login', methods=['GET', 'POST'])
def vuln_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # Уязвимый запрос с конкатенацией строк
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        user = conn.execute(query).fetchone()
        conn.close()

        if user:
            flash('Успешный вход через уязвимость!', 'danger')
            return redirect(url_for('index'))
        else:
            flash('Неверные данные', 'error')

    return render_template('vuln_login.html')


# Защищенная версия входа
@app.route('/secure_login', methods=['GET', 'POST'])
def secure_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = get_db_connection()
        # Параметризованный запрос
        query = "SELECT * FROM users WHERE username = ? AND password = ?"
        user = conn.execute(query, (username, password)).fetchone()
        conn.close()

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash('Вход выполнен безопасно!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверные данные', 'error')

    return render_template('secure_login.html')

# Выход
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы успешно вышли из системы', 'info')
    return redirect(url_for('index'))



if __name__ == '__main__':
    app.run(debug=True)
