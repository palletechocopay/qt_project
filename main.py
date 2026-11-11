import sys
import sqlite3
import json

from PyQt6 import uic
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QMainWindow,
    QApplication,
    QLineEdit,
    QMessageBox
)
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import hashlib
import bcrypt
import secrets


SCRYPT_N = 2**17
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 256 * 1024 * 1024
AAD = b"qt-password-manager:v1"


class PasswordLenError(Exception):
    pass


class IncorrectPasswordError(Exception):
    pass


class AuthDB:
    def __init__(self, er_self):
        con = sqlite3.connect('database.sqlite3')
        cursor = con.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        login TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
        )""")
        cursor.execute("""CREATE TABLE IF NOT EXISTS vault_keys (
        user_id INTEGER NOT NULL,
        n INTEGER NOT NULL,
        r INTEGER NOT NULL,
        p INTEGER NOT NULL,
        maxmem INTEGER NOT NULL,
        salt BLOB NOT NULL,
        nonce BLOB NOT NULL)""")
        con.commit()
        self._key = None
        self.er_self = er_self

    def log_in(self, login, password):
        con = sqlite3.connect('database.sqlite3')
        cursor = con.cursor()
        row = cursor.execute("""SELECT * FROM users WHERE login = ?""", (login, )).fetchone()
        if row[2] is None:
            return False
        else:
            stored_hash = row[2]
            if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                encoded = password.encode("utf-8")
                keys = cursor.execute("""SELECT * FROM vault_keys WHERE user_id = ?""", (row[0],)).fetchone()
                n = keys[1]
                r = keys[2]
                p = keys[3]
                salt = keys[5]
                encoded = password.encode('utf-8')
                self._key = hashlib.scrypt(
                    encoded,
                    salt=salt,
                    n=n,
                    r=r,
                    p=p,
                    maxmem=SCRYPT_MAXMEM,
                    dklen=32)
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
            self.er_self.show_error('Такой логин уже занят')
            return
        try:
            if len(password) > 12:
                hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
                cursor.execute("""INSERT INTO users (login, password) VALUES (?, ?)""", (login, hash_password))
                salt = secrets.token_bytes(16)
                nonce = secrets.token_bytes(12)
                user_id = cursor.lastrowid
                cursor.execute("""INSERT INTO vault_keys 
                (user_id, n, r, p, maxmem, salt, nonce) 
                VALUES (?, ?, ?, ?, ?, ?, ?)""", (user_id, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_MAXMEM, salt, nonce))
                con.commit()
                return True
            raise PasswordLenError
        except sqlite3.IntegrityError:
            self.er_self.show_error('Неверный логин или пароль')
        except PasswordLenError:
            self.er_self.show_error('Пароль должен состоять из хотя бы 12 символов')
        finally:
            con.close()


class MainWindow(QMainWindow):
    def __init__(self):
        self.db = AuthDB(self)
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
        if not login:
            self.show_error('Введите логин')
        elif len(password.split()) > 1:
            self.show_error('Пароль не должен содержать пробельных символов')
        elif not password:
            self.show_error('Введите пароль')
        elif self.db.log_in(login.lower().strip(), password.strip()):
            self.open_main_page()
        else:
            self.show_error('Неверный логин или пароль')

    def reg(self):
        login = self.registerUsernameEdit.text()
        if self.registerPasswordEdit.text() == self.registerConfirmEdit.text():
            password = self.registerPasswordEdit.text()
            if len(password.split()) > 1:
                self.show_error('Пароль не должен содержать пробельных символов')
            elif not password:
                self.show_error('Введите пароль')
            elif self.db.reg(login.lower().strip(), password):
                self.open_log_page()
                QMessageBox.information(self, 'Регистрация', 'Успешно! Теперь войдите в аккаунт')
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
