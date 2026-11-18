import sys
import sqlite3

from PyQt6 import uic
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QMainWindow,
    QApplication,
    QLineEdit,
    QMessageBox,
    QTableWidgetItem
)
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


class MainWindow(QMainWindow):
    def __init__(self):
        """Инициализация основных элементов интерфейса"""
        self.db = AuthDB(self)
        super().__init__()
        uic.loadUi('auth.ui', self)
        self.stackedWidget.setCurrentIndex(0)

        self.messageLabel.hide()
        self.message_timer = QTimer(self)
        self.message_timer.setSingleShot(True)
        self.message_timer.timeout.connect(self.messageLabel.hide)
        self.messageCloseButton.clicked.connect(self.messageLabel.hide)
        self.messageCloseButton.clicked.connect(self.message_timer.stop)

        self.loginShowPasswordCheck.toggled.connect(self._show_log_password)
        self.registerShowPasswordCheck.toggled.connect(self._show_password)
        self.entryShowPasswordCheck.toggled.connect(
            lambda checked: self._show_password(checked, (self.entryPasswordEdit,))
        )
        for link in (self.registerLink, self.loginLink):
            link.setOpenExternalLinks(False)
            link.linkActivated.connect(self._open_page)

        self.loginButton.clicked.connect(self.log_in)
        self.registerButton.clicked.connect(self.reg)
        self.profileButton.clicked.connect(self.profile)
        self.addPasswordButton.clicked.connect(self.add_entry)
        self.logoutButton.clicked.connect(self.show_logout_confirmation)
        self.confirmLogoutYesButton.clicked.connect(self.confirm_logout)
        self.confirmLogoutNoButton.clicked.connect(self.cancel_logout)
        self.confirmEntryButton.clicked.connect(self.confirm_entry)

    def confirm_entry(self):
        """Слот, отвечающий за подтверждение добавления новой записи"""
        url = self.entryUrlEdit.text()
        login = self.entryLoginEdit.text()
        password = self.entryPasswordEdit.text()
        if not url:
            self.show_error('Введите URL')
        elif not login:
            self.show_error('Введите логин')
        elif not password:
            self.show_error('Введите пароль')
        else:
            self.db.add_entry(url, login, password)
            self._show_message('Пароль успешно добавлен!')
            self._clear_entry_dialog()
            self.addEntryDialog.hide()
            self.update_table()

    def _show_message(self, text: str, duration: int=5000):
        """Показывает плашку в левом углу экрана с сообщением"""
        self.messageLabel.setText(text)
        self._position_message()
        self.messageLabel.show()
        self.messageLabel.raise_()
        self.message_timer.start(duration)

    def _position_message(self):
        """Показывает плашку"""
        self.messageLabel.setFixedWidth(min(420, max(1, self.centralwidget.width() - 40)))
        self.messageLabel.adjustSize()
        self.messageLabel.move(
            20, max(0, self.centralwidget.height() - self.messageLabel.height() - 20)
        )
        self.messageCloseButton.move(
            self.messageLabel.width() - self.messageCloseButton.width() - 8,
            (self.messageLabel.height() - self.messageCloseButton.height()) // 2
        )

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if hasattr(self, 'messageCloseButton'):
            self._position_message()

    def show_error(self, text: str):
        """Показывает ошибку"""
        QMessageBox.warning(self, 'Ошибка', text)

    def log_in(self):
        """Слот, отвечающий за отправку в БД запроса о правильности логина и пароля при входе"""
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
            self._show_message('Успешный вход')
        else:
            self.show_error('Неверный логин или пароль')

    def reg(self):
        """Слот, отвечающий за отправку в БД запроса о регистрации логина и пароля при создании аккаунта"""
        login = self.registerUsernameEdit.text()
        if self.registerPasswordEdit.text() == self.registerConfirmEdit.text():
            password = self.registerPasswordEdit.text()
            if len(password.split()) > 1:
                self.show_error('Пароль не должен содержать пробельных символов')
            elif not password:
                self.show_error('Введите пароль')
            elif self.db.reg(login.lower().strip(), password):
                self.open_log_page()
                self._show_message('Успешно! Теперь войдите в аккаунт')
        else:
            self.show_error('Пароли не совпадают')

    def _show_log_password(self, checked):
        """Отвечает за показ пароля в поле """
        if checked:
            mode = QLineEdit.EchoMode.Normal
        else:
            mode = QLineEdit.EchoMode.Password
        self.loginPasswordEdit.setEchoMode(mode)

    def _show_password(self, checked: bool, fields: tuple=None):
        """Слот, отвечающий за показ введенного пароля в полях для ввода пароля"""
        if checked:
            mode = QLineEdit.EchoMode.Normal
        else:
            mode = QLineEdit.EchoMode.Password
        if fields is None:
            fields = (self.registerPasswordEdit, self.registerConfirmEdit)
        for field in fields:
            field.setEchoMode(mode)

    def _open_page(self, target: str):
        """Отвечает за переключение страниц по ссылке внизу экрана при регистрации"""
        if target == 'register':
            self.open_reg_page()
        elif target == 'login':
            self.open_log_page()

    def open_reg_page(self):
        """Показывает страницу регистрации"""
        self._clear_log_areas()
        self.stackedWidget.setCurrentWidget(self.registerPage)

    def open_log_page(self):
        """Показывает страницу входа"""
        self._clear_reg_areas()
        self.stackedWidget.setCurrentWidget(self.loginPage)
 
    def open_main_page(self):
        """Показывает основную страницу"""
        self._clear_log_areas()
        self.stackedWidget.setCurrentWidget(self.mainPage)
        self.update_table()

    def update_table(self):
        """Отображает записи пользователя в таблице"""
        data = self.db.show_table_entries()
        self.passwordsTable.clearContents()
        self.passwordsTable.setRowCount(0)
        for i, row in enumerate(data):
            self.passwordsTable.setRowCount(self.passwordsTable.rowCount() + 1)
            for j, item in enumerate(row):
                self.passwordsTable.setItem(i, j, QTableWidgetItem(item))

    def _clear_log_areas(self):
        """Очищает поля на странице входа"""
        self.loginUsernameEdit.setText('')
        self.loginPasswordEdit.setText('')

    def _clear_reg_areas(self):
        """Очищает поля на странице регистрации"""
        self.registerUsernameEdit.setText('')
        self.registerPasswordEdit.setText('')
        self.registerConfirmEdit.setText('')

    def _clear_entry_dialog(self):
        """Очищает поля на странице ввода новых данных(записей)"""
        self.entryLoginEdit.setText('')
        self.entryPasswordEdit.setText('')
        self.entryUrlEdit.setText('')

    def profile(self):
        """Отображает виджета с профилем"""
        self.profileStackedWidget.setCurrentWidget(self.profileDetailsPage)
        self.profilePage.show()
        geometry = self.profilePage.frameGeometry()
        geometry.moveCenter(self.frameGeometry().center())
        self.profilePage.move(geometry.topLeft())
        self.profilePage.raise_()
        self.profilePage.activateWindow()
        self.profileNameValueLabel.setText(self.db.get_login())

    def add_entry(self):
        """Отображает виджета с формой для новой записи"""
        self.entryShowPasswordCheck.setChecked(False)
        self._clear_entry_dialog()
        self.addEntryDialog.show()
        geometry = self.addEntryDialog.frameGeometry()
        geometry.moveCenter(self.frameGeometry().center())
        self.addEntryDialog.move(geometry.topLeft())
        self.addEntryDialog.raise_()
        self.addEntryDialog.activateWindow()
        self.entryUrlEdit.setFocus()

    def show_logout_confirmation(self):
        """Отображает виджета с подтверждением о выходе из аккаунта"""
        self.profileStackedWidget.setCurrentWidget(self.logoutConfirmPage)
        self.confirmLogoutNoButton.setFocus()

    def cancel_logout(self):
        """Слот, отвечающий за отмену выхода из аккаунта"""
        self.profileStackedWidget.setCurrentWidget(self.profileDetailsPage)
        self.logoutButton.setFocus()

    def confirm_logout(self):
        """Слот, отвечающий за подтвержение выхода из аккаунта"""
        self.db._logout()
        self.profilePage.hide()
        self.profileStackedWidget.setCurrentWidget(self.profileDetailsPage)
        self.profileNameValueLabel.clear()
        self._clear_log_areas()
        self.open_log_page()
        self._show_message('Вы вышли из аккаунта')


class AuthDB:
    def __init__(self, er_self: MainWindow):
        """Инициализация базы данных (создание таблиц, если их нет)"""
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
        cursor.execute("""CREATE TABLE IF NOT EXISTS entries (
        user_id INTEGER NOT NULL,
        url TEXT NOT NULL,
        login TEXT NOT NULL,
        password TEXT NOT NULL,
        nonce BLOB NOT NULL
        )""")
        con.commit()
        con.close()
        self._key = None
        self.er_self = er_self
        self._user_id = None
        self._login = None

    def log_in(self, login: str, password: str) -> bool:
        """Вход в аккаунт: проверка правильность логина и пароля"""
        con = sqlite3.connect('database.sqlite3')
        cursor = con.cursor()
        row = cursor.execute("""SELECT * FROM users WHERE login = ?""", (login, )).fetchone()
        if row is None or row[2] is None:
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
                self._login = row[1]
                self._user_id = row[0]
                return True
            else:
                return False

    def reg(self, login: str, password: str) -> bool:
        """Регистрация: добавления данных в БД"""
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
            if len(password) >= 12:
                hash_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))
                cursor.execute("""INSERT INTO users (login, password) VALUES (?, ?)""", (login, hash_password))
                salt = secrets.token_bytes(16)
                nonce = secrets.token_bytes(12)
                self._user_id = cursor.lastrowid
                cursor.execute("""INSERT INTO vault_keys 
                (user_id, n, r, p, maxmem, salt, nonce) 
                VALUES (?, ?, ?, ?, ?, ?, ?)""", (self._user_id, SCRYPT_N, SCRYPT_R, SCRYPT_P, SCRYPT_MAXMEM, salt, nonce))
                con.commit()
                return True
            raise PasswordLenError
        except sqlite3.IntegrityError:
            self.er_self.show_error('Неверный логин или пароль')
        except PasswordLenError:
            self.er_self.show_error('Пароль должен состоять из хотя бы 12 символов')
        finally:
            con.close()

    def _logout(self):
        """Выход из акканта"""
        self._key = None
        self._user_id = None
        self._login = None

    def get_login(self) -> str:
        """Возвращает логин пользователя"""
        return self._login

    def add_entry(self, url: str, login: str, password: str):
        """Добавления новых паролей в БД"""
        conn = sqlite3.connect('database.sqlite3')
        cursor = conn.cursor()
        nonce = secrets.token_bytes(12)
        cipherpassword = AESGCM(self._key).encrypt(nonce, password.encode("utf-8"), AAD)
        cipherlogin = AESGCM(self._key).encrypt(nonce, login.encode("utf-8"), AAD)
        cursor.execute("""INSERT INTO entries VALUES (?, ?, ?, ?, ?)""", (self._user_id, url, cipherlogin, cipherpassword, nonce))
        conn.commit()
        conn.close()

    def show_table_entries(self) -> list:
        """Возвращает все имеющие записи пользователя"""
        conn = sqlite3.connect('database.sqlite3')
        cursor = conn.cursor()
        cipher_user_data = cursor.execute("""SELECT * FROM entries WHERE user_id = ?""", (self._user_id, )).fetchall()
        plain_user_data = []
        for _, url, login, _, nonce in cipher_user_data:
            plainlogin = AESGCM(self._key).decrypt(nonce, login, AAD).decode('utf-8')
            plain_user_data.append((url, plainlogin))
        return plain_user_data


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
