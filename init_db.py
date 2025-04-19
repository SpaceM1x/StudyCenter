# init_db.py

import sqlite3

def init_db():
    connection = sqlite3.connect('education_center.db')
    with connection:
        # Добавляем в функцию init_db()
        connection.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT,          -- Секрет для 2FA
                is_2fa_enabled BOOLEAN     -- Флаг активности 2FA
            )
        ''')

        # Таблица преподавателей с дополнительным полем phone
        connection.execute('''
            CREATE TABLE IF NOT EXISTS teachers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                subject TEXT NOT NULL,
                email TEXT NOT NULL,
                phone TEXT
            );
        ''')
        # Таблица учеников
        connection.execute('''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL
            );
        ''')
        # Таблица предметов
        connection.execute('''
            CREATE TABLE IF NOT EXISTS subjects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL
            );
        ''')
        # Таблица расписания
        connection.execute('''
            CREATE TABLE IF NOT EXISTS schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER,
                subject_id INTEGER,
                student_id INTEGER,
                date TEXT,
                time TEXT,
                FOREIGN KEY(teacher_id) REFERENCES teachers(id),
                FOREIGN KEY(subject_id) REFERENCES subjects(id),
                FOREIGN KEY(student_id) REFERENCES students(id)
            );
        ''')
    connection.close()
    print("База данных успешно инициализирована.")

if __name__ == '__main__':
    init_db()
