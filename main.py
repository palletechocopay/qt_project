import sys
import sqlite3

from PyQt6 import uic
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QMainWindow,
    QApplication,
    QLineEdit,
    QMessageBox
)

import bcrypt

class AuthDB:
    def __init__(self):
        con = sqlite3.connect('database.sqlite3')
        cursor = con.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        )""")
        con.commit()

    def log_in(self, login, password):
        con = sqlite3.connect('database.sqlite3')
        cursor = con.cursor()
        row = cursor.execute("""SELECT password FROM users WHERE login = ?""", (login, )).fetchone()
        con.close()
        if row[0] is None:
            return False
        else:
            stored_hash = row[0]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                return True
            else:
                return False   
        

    def reg(self, login, password):
        con = sqlite3.connect('database.sqlite3')
        cursor = con.cursor()
        cursor.execute(
            "SELECT EXISTS(SELECT * FROM users WHERE login = ?)",
            (login,)
        )
        if cursor.fetchone()[0]:
            return False
        try:
            hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
            cursor.execute("""INSERT INTO users (login, password) VALUES (?, ?)""", (login, hash_password))
            con.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        finally:
            con.close()
        

class MainWindow(QMainWindow):
    def __init__(self):
        self.db = AuthDB()
        super().__init__()
        uic.loadUi('auth.ui', self)
        self.stackedWidget.setCurrentIndex(0)

        self.loginShowPasswordCheck.toggled.connect(self._show_log_password)
        self.registerShowPasswordCheck.toggled.connect(self._show_reg_password)
        for link in (self.registerLink, self.loginLink):
            link.setOpenExternalLinks(False)
            link.linkActivated.connect(self._open_page)

        self.loginButton.clicked.connect(self.log_in)
        self.registerButton.clicked.connect(self.reg)

    def show_error(self, text):
        QMessageBox.warning(self, 'Ошибка', text)

    def log_in(self):
        login = self.loginUsernameEdit.text()
        password = self.loginPasswordEdit.text()
        if self.db.log_in(login.lower().strip(), password):
            self.open_main_page()
        else:
            self.show_error('Неверный логин или пароль')

    def reg(self):
        login = self.registerUsernameEdit.text()
        if self.registerPasswordEdit.text() == self.registerConfirmEdit.text():
            password = self.registerPasswordEdit.text()
            if self.db.reg(login.lower().strip(), password):
                self.open_log_page()
                QMessageBox.information(self, 'Регистрация', 'Успешно! Теперь войдите в аккаунт')
            else:
                self.show_error('Такой логин уже занят! Попробуйте что-нибудь другое')
        else:
            self.show_error('Пароли не совпадают')

    def _show_log_password(self, checked):
        if checked:
            mode = QLineEdit.EchoMode.Normal
        else:
            mode = QLineEdit.EchoMode.Password
        self.loginPasswordEdit.setEchoMode(mode)

    def _show_reg_password(self, checked):
        if checked:
            mode = QLineEdit.EchoMode.Normal
        else:
            mode = QLineEdit.EchoMode.Password
        self.registerPasswordEdit.setEchoMode(mode)
        self.registerConfirmEdit.setEchoMode(mode)

    def _open_page(self, target):
        if target == 'register':
            self.open_reg_page()
        elif target == 'login':
            self.open_log_page()

    def open_reg_page(self):
        self._clear_log_areas()
        self.stackedWidget.setCurrentWidget(self.registerPage)

    def open_log_page(self):
        self._clear_reg_areas()
        self.stackedWidget.setCurrentWidget(self.loginPage)
 
    def open_main_page(self):
        self._clear_log_areas()
        self.stackedWidget.setCurrentWidget(self.mainPage)

    def _clear_log_areas(self):
        self.loginUsernameEdit.setText('')
        self.loginPasswordEdit.setText('')

    def _clear_reg_areas(self):
        self.registerUsernameEdit.setText('')
        self.registerPasswordEdit.setText('')
        self.registerConfirmEdit.setText('')


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())