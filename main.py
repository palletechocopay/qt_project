import sys
import sqlite3

from PyQt6 import uic
from PyQt6.QtCore import Qt, QTimer
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
        self.detailsShowPasswordCheck.toggled.connect(
            lambda checked: self._show_password(checked, (self.detailsPasswordEdit,))
        )
        self.passwordsTable.cellClicked.connect(self.open_entry)
        self.closeEntryDetailsButton.clicked.connect(self.entryDetailsDialog.close)
        self.copyPasswordButton.clicked.connect(self.copy_password)
        self.entryDetailsDialog.finished.connect(self._clear_entry_details)
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

        self.passwordsTable.setSortingEnabled(True)

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
            self.show_information('Пароль успешно добавлен!')
            self._clear_entry_dialog()
            self.addEntryDialog.hide()
            self.update_table()

    def set_message_color(self, 
                          background,
                          text='#1D6E54',
                          border='#B9DDC8'):
        self.messageLabel.setStyleSheet(f"""
            QLabel#messageLabel {{
                background-color: {background};
                color: {text};
                border: 1px solid {border};
                border-radius: 8px;
                padding: 10px;
                padding-right: 40px;
            }}
        """)

    def show_information(self, text: str):
        """отображает информацию пользователю(все, кроме ошибок)"""
        self.set_message_color(background='#E5F3EB',
                                text='#1D6E54',
                                border='#B9DDC8')
        self._show_message(text)

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
        self.set_message_color(background='#FDECEC',
                                text='#B71C1C',
                                border='#EF9A9A')
        self._show_message(text)


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
            self.show_information('Успешный вход')
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
                self.show_information('Успешно! Теперь войдите в аккаунт')
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
        for i, (entry_id, url, login) in enumerate(data):
            self.passwordsTable.setRowCount(self.passwordsTable.rowCount() + 1)
            for j, value in enumerate((url, login)):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, entry_id)
                self.passwordsTable.setItem(i, j, item)

    def open_entry(self, row: int, column: int):
        """Открывает выбранную запись для просмотра."""
        item = self.passwordsTable.item(row, column)
        if item is None:
            return
        entry = self.db.get_entry(item.data(Qt.ItemDataRole.UserRole))
        if entry is None:
            self.entryDetailsDialog.close()
            self.show_error('Запись недоступна')
            return
        self._clear_entry_details()
        url, login, password = entry
        self.detailsUrlEdit.setText(url)
        self.detailsLoginEdit.setText(login)
        self.detailsPasswordEdit.setText(password)
        for field in (self.detailsUrlEdit, self.detailsLoginEdit, self.detailsPasswordEdit):
            field.setCursorPosition(0)
        self.entryDetailsDialog.show()
        geometry = self.entryDetailsDialog.frameGeometry()
        geometry.moveCenter(self.frameGeometry().center())
        self.entryDetailsDialog.move(geometry.topLeft())
        self.entryDetailsDialog.raise_()
        self.entryDetailsDialog.activateWindow()

    def copy_password(self):
        """Копирует пароль открытой записи в буфер обмена."""
        QApplication.clipboard().setText(self.detailsPasswordEdit.text())
        self.show_information('Пароль скопирован')

    def _clear_entry_details(self):
        """Скрывает пароль и очищает поля просмотра записи."""
        self.detailsShowPasswordCheck.setChecked(False)
        self.detailsUrlEdit.clear()
        self.detailsLoginEdit.clear()
        self.detailsPasswordEdit.clear()

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
        self.entryDetailsDialog.close()
        self._clear_entry_details()
        self.passwordsTable.setRowCount(0)
        self.db._logout()
        self.profilePage.hide()
        self.profileStackedWidget.setCurrentWidget(self.profileDetailsPage)
        self.profileNameValueLabel.clear()
        self._clear_log_areas()
        self.open_log_page()
        self.show_information('Вы вышли из аккаунта')


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
            con.close()
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
                con.close()
                return True
            else:
                con.close()
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
        try:
            cursor.execute("""INSERT INTO entries VALUES (?, ?, ?, ?, ?)""", (self._user_id, url, cipherlogin, cipherpassword, nonce))
        finally:
            conn.commit()
            conn.close()

    def show_table_entries(self) -> list:
        """Возвращает идентификатор, ссылку и логин записей пользователя."""
        conn = sqlite3.connect('database.sqlite3')
        try:
            cipher_user_data = conn.execute(
                'SELECT rowid, url, login, nonce FROM entries WHERE user_id = ? ORDER BY rowid',
                (self._user_id,)
            ).fetchall()
        finally:
            conn.close()
        plain_user_data = []
        for entry_id, url, login, nonce in cipher_user_data:
            plainlogin = AESGCM(self._key).decrypt(nonce, login, AAD).decode('utf-8')
            plain_user_data.append((entry_id, url, plainlogin))
        return plain_user_data

    def get_entry(self, entry_id: int):
        """Возвращает расшифрованную запись текущего пользователя."""
        if self._user_id is None or self._key is None:
            return None
        conn = sqlite3.connect('database.sqlite3')
        try:
            row = conn.execute(
                'SELECT url, login, password, nonce FROM entries WHERE rowid = ? AND user_id = ?',
                (entry_id, self._user_id)
            ).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        url, login, password, nonce = row
        cipher = AESGCM(self._key)
        return (
            url,
            cipher.decrypt(nonce, login, AAD).decode('utf-8'),
            cipher.decrypt(nonce, password, AAD).decode('utf-8')
        )


if __name__ == "__main__":
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())
