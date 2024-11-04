import tkinter as tk
from tkinter import messagebox, ttk
import sqlite3
import time
import getpass
import socket

# Подключение к базе данных
conn = sqlite3.connect('app.db')
c = conn.cursor()

# Создание таблиц пользователей и аудита
c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password TEXT,
                failed_attempts INTEGER DEFAULT 0,
                blocked_until INTEGER DEFAULT 0
            )''')

c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY,
                event_time TEXT,
                user TEXT,
                event_type TEXT,
                workstation TEXT,
                os_user TEXT,
                details TEXT
            )''')

c.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', 'pass')")

# Создание таблицы для хранения настроек
c.execute('''CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY,
                max_failed_attempts INTEGER DEFAULT 3,
                block_time INTEGER DEFAULT 600,
                inactivity_timeout INTEGER DEFAULT 300
            )''')

# Инициализация настроек по умолчанию, если их нет
c.execute('SELECT * FROM settings WHERE id=1')
if c.fetchone() is None:
    c.execute('INSERT INTO settings (id, max_failed_attempts, block_time, inactivity_timeout) VALUES (1, 3, 600, 300)')

conn.commit()

# Загрузка настроек из базы данных
c.execute('SELECT max_failed_attempts, block_time, inactivity_timeout FROM settings WHERE id=1')
settings = c.fetchone()
MAX_FAILED_ATTEMPTS, BLOCK_TIME, INACTIVITY_TIMEOUT = settings

# Запись в журнал аудита
def log_event(user, event_type, details):
    event_time = time.strftime('%Y-%m-%d %H:%M:%S')
    os_user = getpass.getuser()  # Имя пользователя ОС
    workstation = socket.gethostname()  # Имя рабочей станции
    c.execute('INSERT INTO audit_log (event_time, user, event_type, workstation, os_user, details) VALUES (?, ?, ?, ?, ?, ?)',
              (event_time, user, event_type, workstation, os_user, details))
    conn.commit()

# Функция авторизации
def login():
    username = entry_username.get()
    password = entry_password.get()

    # Проверка существования пользователя
    c.execute('SELECT password, failed_attempts, blocked_until FROM users WHERE username=?', (username,))
    result = c.fetchone()

    if result is None:
        messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль.")
        log_event(username, "Failed Login", "Неверное имя пользователя")
        return

    db_password, failed_attempts, blocked_until = result

    # Проверка блокировки пользователя
    current_time = int(time.time())
    if current_time < blocked_until:
        messagebox.showerror("Ошибка", f"Учётная запись заблокирована. Попробуйте позже.")
        log_event(username, "Blocked Login Attempt", "Попытка входа при заблокированной учётной записи")
        return



    # Проверка пароля
    if password == db_password:
        messagebox.showinfo("Успех", "Успешный вход!")
        log_event(username, "Successful Login", "Пользователь успешно вошел в систему")
        reset_failed_attempts(username)
        open_app_window(username)
    else:
        failed_attempts += 1
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            block_time = current_time + BLOCK_TIME  # Время блокировки
            c.execute('UPDATE users SET failed_attempts=?, blocked_until=? WHERE username=?',
                      (failed_attempts, block_time, username))
            conn.commit()
            messagebox.showerror(f"Ошибка", "Учётная запись заблокирована после {failed_attempts} неудачных попыток.")
            log_event(username, "Account Blocked", f"Учётная запись заблокирована после {failed_attempts} неудачных попыток.")
        else:
            c.execute('UPDATE users SET failed_attempts=? WHERE username=?', (failed_attempts, username))
            conn.commit()
            messagebox.showerror("Ошибка", f"Неверный пароль. Осталось попыток: {MAX_FAILED_ATTEMPTS - failed_attempts}")
            log_event(username, "Failed Login", f"Неверный пароль. Попытки: {failed_attempts}")

# Сброс неудачных попыток
def reset_failed_attempts(username):
    c.execute('UPDATE users SET failed_attempts=0 WHERE username=?', (username,))
    conn.commit()

# Открытие основного окна приложения
def open_app_window(username):
    # Закрытие окна входа
    login_window.destroy()

    # Окно приложения
    app_window = tk.Tk()
    app_window.title("Приложение")

    tk.Label(app_window, text=f"Добро пожаловать, {username}!").pack()

    # Кнопка выхода
    def logout():
        log_event(username, "Logout", "Пользователь вышел из системы")
        app_window.destroy()

    tk.Button(app_window, text="Выйти", command=logout).pack()

    # Открытие журнала аудита
    def open_audit_log():
        audit_window = tk.Toplevel(app_window)
        audit_window.title("Журнал аудита")

        tree = ttk.Treeview(audit_window, columns=("event_time", "user", "workstation", "event_type", "details"), show="headings")
        tree.heading("event_time", text="Дата и время")
        tree.heading("user", text="Пользователь")
        tree.heading("workstation", text="Раб. станция")
        tree.heading("event_type", text="Событие")
        tree.heading("details", text="Детали")

        tree.pack(fill=tk.BOTH, expand=True)

        # Заполнение данными из базы
        c.execute('SELECT event_time, user, workstation, event_type, details FROM audit_log')
        rows = c.fetchall()
        for row in rows:
            tree.insert("", tk.END, values=row)

    tk.Button(app_window, text="Журнал аудита", command=open_audit_log).pack()

    # Открытие настроек безопасности
    def open_settings():
        settings_window = tk.Toplevel(app_window)
        settings_window.title("Настройки безопасности")

        tk.Label(settings_window, text="Количество неудачных попыток до блокировки:").grid(row=0, column=0)
        attempts_var = tk.IntVar(value=MAX_FAILED_ATTEMPTS)
        tk.Entry(settings_window, textvariable=attempts_var).grid(row=0, column=1)

        tk.Label(settings_window, text="Время блокировки (в секундах):").grid(row=1, column=0)
        block_time_var = tk.IntVar(value=BLOCK_TIME)
        tk.Entry(settings_window, textvariable=block_time_var).grid(row=1, column=1)

        tk.Label(settings_window, text="Время простоя для блокировки (в секундах):").grid(row=2, column=0)
        inactivity_timeout_var = tk.IntVar(value=INACTIVITY_TIMEOUT)
        tk.Entry(settings_window, textvariable=inactivity_timeout_var).grid(row=2, column=1)

        def save_settings():
            global MAX_FAILED_ATTEMPTS, BLOCK_TIME, INACTIVITY_TIMEOUT
            MAX_FAILED_ATTEMPTS = attempts_var.get()
            BLOCK_TIME = block_time_var.get()
            INACTIVITY_TIMEOUT = inactivity_timeout_var.get()

            # Обновление настроек в базе данных
            c.execute('UPDATE settings SET max_failed_attempts=?, block_time=?, inactivity_timeout=? WHERE id=1',
                      (MAX_FAILED_ATTEMPTS, BLOCK_TIME, INACTIVITY_TIMEOUT))
            conn.commit()

            settings_window.destroy()
            messagebox.showinfo("Настройки", "Настройки сохранены.")
            log_event(username, "Settings Change", "Изменены параметры безопасности")

        tk.Button(settings_window, text="Сохранить", command=save_settings).grid(row=3, column=0, columnspan=2)

    tk.Button(app_window, text="Настройки", command=open_settings).pack()

    # Таймер бездействия
    def on_inactivity():
        log_event(username, "Session Timeout", "Сеанс завершён из-за бездействия")
        messagebox.showwarning("Тайм-аут", "Сеанс завершён из-за бездействия.")
        app_window.destroy()

    app_window.after(INACTIVITY_TIMEOUT * 1000, on_inactivity)

    app_window.mainloop()


# Интерфейс окна авторизации
login_window = tk.Tk()
login_window.title("Авторизация")

tk.Label(login_window, text="Имя пользователя").grid(row=0, column=0)
tk.Label(login_window, text="Пароль").grid(row=1, column=0)

entry_username = tk.Entry(login_window)
entry_password = tk.Entry(login_window, show="*")
entry_username.grid(row=0, column=1)
entry_password.grid(row=1, column=1)

tk.Button(login_window, text="Войти", command=login).grid(row=2, column=0, columnspan=2)

log_event("System", "System Start", "Система запущена")


def on_close():
    log_event("System", "System Stop", "Система остановлена")
    login_window.destroy()  # Закрытие окна


login_window.protocol("WM_DELETE_WINDOW", on_close)

login_window.mainloop()

# Закрытие соединения с базой данных при завершении работы
conn.close()

conn.commit()


# Запись в журнал аудита
def log_event(user, event_type, details):
    event_time = time.strftime('%Y-%m-%d %H:%M:%S')
    os_user = getpass.getuser()  # Имя пользователя ОС
    workstation = socket.gethostname()  # Имя рабочей станции
    c.execute(
        'INSERT INTO audit_log (event_time, user, event_type, workstation, os_user, details) VALUES (?, ?, ?, ?, ?, ?)',
        (event_time, user, event_type, workstation, os_user, details))
    conn.commit()


# Функция авторизации
def login():
    username = entry_username.get()
    password = entry_password.get()

    # Проверка существования пользователя
    c.execute('SELECT password, failed_attempts, blocked_until FROM users WHERE username=?', (username,))
    result = c.fetchone()

    if result is None:
        messagebox.showerror("Ошибка", "Неверное имя пользователя или пароль.")
        log_event(username, "Failed Login", "Неверное имя пользователя")
        return

    db_password, failed_attempts, blocked_until = result

    # Проверка блокировки пользователя
    current_time = int(time.time())
    if current_time < blocked_until:
        messagebox.showerror("Ошибка", f"Учётная запись заблокирована. Попробуйте позже.")
        log_event(username, "Blocked Login Attempt", "Попытка входа при заблокированной учётной записи")
        return



    # Проверка пароля
    if password == db_password:
        messagebox.showinfo("Успех", "Успешный вход!")
        log_event(username, "Successful Login", "Пользователь успешно вошел в систему")
        reset_failed_attempts(username)
        open_app_window(username)
    else:
        failed_attempts += 1
        if failed_attempts >= MAX_FAILED_ATTEMPTS:
            block_time = current_time + 600  # Блокировка на 10 минут
            c.execute('UPDATE users SET failed_attempts=?, blocked_until=? WHERE username=?',
                      (failed_attempts, block_time, username))
            conn.commit()
            messagebox.showerror("Ошибка", "Учётная запись заблокирована после 3 неудачных попыток.")
            log_event(username, "Account Blocked", f"Учётная запись заблокирована после {failed_attempts} неудачных попыток.")
        else:
            c.execute('UPDATE users SET failed_attempts=? WHERE username=?', (failed_attempts, username))
            conn.commit()
            messagebox.showerror("Ошибка", f"Неверный пароль. Осталось попыток: {MAX_FAILED_ATTEMPTS - failed_attempts}")
            log_event(username, "Failed Login", f"Неверный пароль. Попытки: {failed_attempts}")

# Сброс неудачных попыток
def reset_failed_attempts(username):
    c.execute('UPDATE users SET failed_attempts=0 WHERE username=?', (username,))
    conn.commit()

# Открытие основного окна приложения
def open_app_window(username):
    # Закрытие окна входа
    login_window.destroy()

    # Окно приложения
    app_window = tk.Tk()
    app_window.title("Приложение")

    tk.Label(app_window, text=f"Добро пожаловать, {username}!").pack()

    # Кнопка выхода
    def logout():
        log_event(username, "Logout", "Пользователь вышел из системы")
        app_window.destroy()

    tk.Button(app_window, text="Выйти", command=logout).pack()

    # Таймер бездействия
    def on_inactivity():
        log_event(username, "Session Timeout", "Сеанс завершён из-за бездействия")
        messagebox.showwarning("Тайм-аут", "Сеанс завершён из-за бездействия.")
        app_window.destroy()

    app_window.after(INACTIVITY_TIMEOUT * 1000, on_inactivity)

    app_window.mainloop()

# Интерфейс окна авторизации
login_window = tk.Tk()
login_window.title("Авторизация")

tk.Label(login_window, text="Имя пользователя").grid(row=0, column=0)
tk.Label(login_window, text="Пароль").grid(row=1, column=0)

entry_username = tk.Entry(login_window)
entry_password = tk.Entry(login_window, show="*")
entry_username.grid(row=0, column=1)
entry_password.grid(row=1, column=1)

tk.Button(login_window, text="Войти", command=login).grid(row=2, column=0, columnspan=2)

log_event("System", "System Start", "Система запущена")
login_window.protocol("WM_DELETE_WINDOW", lambda: log_event("System", "System Stop", "Система остановлена"))

login_window.mainloop()

# Закрытие соединения с базой данных при завершении работы
conn.close()
