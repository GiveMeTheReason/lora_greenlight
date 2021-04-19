#!/usr/bin/env python3

from pyzbar.pyzbar import decode
from os import remove, getenv
import sys
import argparse
import cv2
import exifread
import re
import requests
import logging
from datetime import datetime

from aiogram import Bot, Dispatcher, executor, types
from aiogram.utils.exceptions import TelegramAPIError
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
from aiogram.contrib.fsm_storage.mongo import MongoStorage
from prometheus_client import start_http_server, Counter

# ------------------------------------------------------------

def createParser():
    """
    Command-line argument parser
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--token", default=None)
    parser.add_argument("--server", default=None)
    parser.add_argument("--size", type=int, default=None)
    parser.add_argument("--relogin", type=int, default=None)
    parser.add_argument("--mongo_db", default=None)
    parser.add_argument("--mongo_user", default=None)
    parser.add_argument("--mongo_pass", default=None)
    parser.add_argument("--mongo_host", default=None)
    parser.add_argument("--mongo_port", type=int, default=None)
    parser.add_argument("--loglevel", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--doc_path", default=None)
    return parser

parser = createParser()
variables = parser.parse_args()

# Configure logging
loglevel = variables.loglevel or getenv("LOGLEVEL", default="WARNING")
if not loglevel:
    loglevel = "WARNING"
log_format = "%(asctime)s:%(name)s:%(levelname)s:%(message)s line:%(lineno)d"

# Set loglevel from console (default=WARNING)
fl = False
if loglevel.upper() == "DEBUG":
    logging.basicConfig(level=logging.DEBUG, format=log_format)
elif loglevel.upper() == "INFO":
    logging.basicConfig(level=logging.INFO, format=log_format)
elif loglevel.upper() == "WARNING":
    logging.basicConfig(level=logging.WARNING, format=log_format)
elif loglevel.upper() == "ERROR":
    logging.basicConfig(level=logging.ERROR, format=log_format)
elif loglevel.upper() == "CRITICAL":
    logging.basicConfig(level=logging.CRITICAL, format=log_format)
else:
    logging.basicConfig(level=logging.WARNING, format=log_format)
    loglevel = "WARNING"
    fl = True
if fl:
    logging.warning(f"\"{loglevel}\" loglevel does not exist.\n\
        Use one: DEBUG, INFO, WARNING, ERROR, CRITICAL")
logging.warning(f"Logging level set: {loglevel.upper()}")

# Filter info in logging
class SensitiveFormatter(logging.Formatter):
    """Filters text info that is not command or email"""
    @staticmethod
    def _filter(s):
        return re.sub(r"\"text\":\"[^/@\s]+\"", "\"text\":\"*** SECRET ***\"", s)

    def format(self, record):
        original = logging.Formatter.format(self, record)
        return self._filter(original)

class TracebackInfoFilter(logging.Filter):
    """Clear or restore the exception on log records"""
    def __init__(self, clear=True):
        self.clear = clear
    def filter(self, record):
        if self.clear:
            record._exc_info_hidden, record.exc_info = record.exc_info, None
            # clear the exception traceback text cache, if created.
            record.exc_text = None
        elif hasattr(record, "_exc_info_hidden"):
            record.exc_info = record._exc_info_hidden
            del record._exc_info_hidden
        return True

tglogger = logging.getLogger("aiogram")
for handler in logging.root.handlers:
    handler.setFormatter(SensitiveFormatter(log_format))
    handler.addFilter(TracebackInfoFilter())

# Set API token from @BotFather
API_TOKEN = variables.token or getenv("BOT_TOKEN")
if API_TOKEN:
    logging.info("API-token for telegram bot set")
else:
    logging.error("API-token is not provided! Shutting down!")
    sys.exit("API-token is not provided!")

# Set server domain
server_path = variables.server or getenv("SERVER_PATH")
if server_path:
    if server_path[-1] == "/":
        server_path = server_path[:-1]
    logging.info(f"Server set: {server_path}")
else:
    logging.error("Server is not provided! Shutting down!")
    sys.exit("Server is not provided!")

# Set photo max size in MB (megabytes). default=20
try:
    allowed_size = variables.size or getenv("ALLOWED_SIZE", default="20")
    if allowed_size:
        allowed_size = int(allowed_size)
    else:
        allowed_size = 20
except Exception as e:
    logging.error("ALLOWED_SIZE must be integer!")
    logging.error(str(e))
    sys.exit("ALLOWED_SIZE must be positive integer!")
if allowed_size <= 0:
    logging.error(f"Allowed size set to negative: {allowed_size} MB")
    sys.exit("ALLOWED_SIZE must be positive integer!")
logging.info(f"Maximum file size set: {allowed_size} MB")

# Set hours for manual re-login. default=1
try:
    hours_to_relogin = variables.relogin or getenv("HOURS_TO_RELOGIN", default="1")
    if hours_to_relogin:
        hours_to_relogin = int(hours_to_relogin)
    else:
        hours_to_relogin = 24
except Exception as e:
    logging.error("HOURS_TO_RELOGIN must be positive integer!")
    logging.error(str(e))
    sys.exit("HOURS_TO_RELOGIN must be positive integer!")
if hours_to_relogin == 0:
    logging.info(f"Until manual re-login set: {hours_to_relogin} hours\n\
        Sessions will not be closed")
elif hours_to_relogin < 0:
    logging.warning(f"Until manual re-login set negative: {hours_to_relogin} hours")
    sys.exit("HOURS_TO_RELOGIN must be positive integer!")
else:
    logging.info(f"Until manual re-login set: {hours_to_relogin} hours")

# Set mongodb init data
mongo_db = variables.mongo_db or getenv("MONGO_DATABASE", default="aiogram_fsm")
if not mongo_db:
    mongo_db = "aiogram_fsm"
logging.info(f"Mongo database set: {mongo_db}")

mongo_user = variables.mongo_user or getenv("MONGO_USERNAME")
if not mongo_user:
    mongo_user = None
    logging.info("Mongo username is not provided (None)")
else:
    logging.info(f"Mongo username set: {mongo_user}")

mongo_pass = variables.mongo_pass or getenv("MONGO_PASSWORD")
if not mongo_pass:
    mongo_pass = None
    logging.info("Mongo password is not provided (None)")
else:
    logging.info(f"Mongo password set")

mongo_host = variables.mongo_host or getenv("MONGO_HOST", default="localhost")
if not mongo_host:
    mongo_host = "localhost"
logging.info(f"Mongo host set: {mongo_host}")

try:
    mongo_port = variables.mongo_port or getenv("MONGO_PORT", default="27017")
    if mongo_port:
        mongo_port = int(mongo_port)
    else:
        mongo_port = 27017
except Exception as e:
    logging.error("MONGO_PORT must be positive integer!")
    logging.error(str(e))
    sys.exit("MONGO_PORT must be positive integer!")
if mongo_port < 0:
    logging.error("MONGO_PORT must be positive integer!")
    logging.error(str(e))
    sys.exit("MONGO_PORT must be positive integer!")
logging.info(f"Mongo port set: {mongo_port}")

# Set port for metrics
try:
    metrics_port = variables.port or getenv("PORT", default="9090")
    if metrics_port:
        metrics_port = int(metrics_port)
    else:
        metrics_port = 9090
except Exception as e:
    logging.error("PORT must be positive integer!")
    logging.error(str(e))
    sys.exit("PORT must be positive integer!")
if metrics_port < 0:
    logging.error("PORT must be positive integer!")
    logging.error(str(e))
    sys.exit("PORT must be positive integer!")
logging.info(f"Metrics port set: {metrics_port}")

# Set folder for downloaded documents
save_dir = variables.doc_path or getenv("DOCUMENTS_PATH", default="")
if not save_dir:
    save_dir = ""
try:
    open(save_dir + "/" + "dir_check.md", "wb").write(bytes("True".encode("UTF-8")))
    remove(save_dir + "/" + "dir_check.md")
except Exception as e:
    logging.error("Error with DOCUMENTS_PATH!")
    logging.error(str(e))
    sys.exit("Error with DOCUMENTS_PATH!")
logging.info(f"Documents path set: {save_dir}")

# ------------------------------------------------------------

# Metrics list
prom_error_counter = Counter("error_counter", "Number of errors occured in total")
prom_authorization_error = Counter("authorization_error", "Number of authorization errors")
prom_server_error = Counter("server_error", "Number of server errors")
prom_controllers_get_error = Counter("controllers_get_error", "Number of controller-list-get errors")
prom_wrong_filetype_error = Counter("wrong_filetype_error", "Number of wrong document format recieved")
prom_wrong_filesize_error = Counter("wrong_filesize_error", "Number of wrong document size recieved")
prom_file_download_error = Counter("file_download_error", "Number of failed downloads")
prom_no_gps_error = Counter("no_gps_error", "Number of documents without GPS data")
prom_no_qr_error = Counter("no_qr_error", "Number of documents without QR data")
prom_telegram_exeption_error = Counter("telegram_exeption_error", "Number of Telegram Exceptions occured")

prom_message_counter = Counter("message_counter", "Number of messages received in total")
prom_get_list_counter = Counter("get_list_counter", "Number of button \"get list\" pressed in total")
prom_get_controller_counter = Counter("get_controller_counter", "Number of button \"get controller\" pressed in total")
prom_successful_manual_login = Counter("successful_manual_login", "Number of successful manual logins")
prom_successful_auto_relogin = Counter("successful_auto_relogin", "Number of successful auto re-logins")
prom_light_added = Counter("light_added", "Number of lights successfully added")

# ------------------------------------------------------------

# States for FSM
class UserState(StatesGroup):
    unauthorized = State()
    email = State()
    password = State()
    authorized = State()
    choose_controller = State()
    upload_photos = State()

# Set list of content types
content_types = [
    "text", "audio", "document", "photo", "sticker", "video",
    "video_note", "voice", "location", "contact", "new_chat_members",
    "left_chat_member", "new_chat_title", "new_chat_photo", "delete_chat_photo",
    "group_chat_created", "supergroup_chat_created", "channel_chat_created",
    "migrate_to_chat_id", "migrate_from_chat_id", "pinned_message",
    ]

# Combine URI string for MongoDB connection
uri = "mongodb://"
if mongo_user and mongo_pass:
    uri += f"{mongo_user}:{mongo_pass}@"
uri += f"{mongo_host}:{mongo_port}"
uri += "/?serverSelectionTimeoutMS=3600000"

# Initialize bot and dispatcher and FSM (finite state machine)
bot = Bot(token=API_TOKEN, timeout=20)
storage = MongoStorage(uri=uri)
dp = Dispatcher(bot, storage=storage)

# ------------------------------------------------------------

def convert_to_degrees(value):
    """
    Helper function to convert the GPS coordinates stored in the EXIF to degrees in float format
    :param value:
    :type value: exifread.utils.Ratio
    :rtype: float
    """
    try:
        d = float(value.values[0].num) / float(value.values[0].den)
        m = float(value.values[1].num) / float(value.values[1].den)
        s = float(value.values[2].num) / float(value.values[2].den)
        degrees = round(d + (m / 60.0) + (s / 3600.0), 6)
    except Exception as e:
        logging.error("Exception during convert_to_degrees occurred")
        logging.error(str(e))
    return degrees


def find_GPS(file_name):
    """
    Returns GPS Latitude and Longitude. Returns None if "not found"
    """
    f = open(file_name, "rb")
    tags = exifread.process_file(f, details=False)
    f.close()
    latitude = tags.get("GPS GPSLatitude", None)
    latitude_ref = tags.get("GPS GPSLatitudeRef", None)
    longitude = tags.get("GPS GPSLongitude", None)
    longitude_ref = tags.get("GPS GPSLongitudeRef", None)
    logging.debug("GPS extracted")
    if latitude and latitude_ref and longitude and longitude_ref:
        latitude = convert_to_degrees(latitude)
        # Check North
        if latitude_ref.values[0] != "N":
            lat = -lat
        longitude = convert_to_degrees(longitude)
        # Check East
        if longitude_ref.values[0] != "E":
            lon = -lon
    return latitude, longitude


def find_QR(file_name):
    """
    Returns QR-code information
    Returns None if "not found"
    Returns False if found more than one code
    """
    # Open cv2-image in gray scale
    f = cv2.imread(file_name, cv2.IMREAD_GRAYSCALE)

    # Try standart threshold
    threshold, threshold_image = cv2.threshold(f, 127, 255, 0)
    # Symbols = 64 for QR-codes
    barcodes = decode(threshold_image, symbols=[64])
    logging.debug(f"find_QR try threshold: {threshold}")
    logging.debug(f"find_QR detected: {barcodes}")
    # Check if exactly one code scanned
    codes = []
    for barcode in barcodes:
        codes.append(barcode.data.decode("utf-8"))

    # If not found, try other thresholds
    if not codes:
        # Scan thresholds = 102/77/52
        for i in range(102,51,-25):
            threshold, threshold_image = cv2.threshold(f, i, 255, 0)
            barcodes = decode(threshold_image, symbols=[64])
            logging.debug(f"find_QR try threshold: {threshold}")
            logging.debug(f"find_QR detected: {barcodes}")
            # Collect all scanned info
            for barcode in barcodes:
                codes.append(barcode.data.decode("utf-8"))
            # If found then break
            if codes:
                break
        # Scan thresholds = 152/177/202
        for i in range(152,203,25):
            threshold, threshold_image = cv2.threshold(f, i, 255, 0)
            barcodes = decode(threshold_image, symbols=[64])
            logging.debug(f"find_QR try threshold: {threshold}")
            logging.debug(f"find_QR detected: {barcodes}")
            # Collect all scanned info
            for barcode in barcodes:
                codes.append(barcode.data.decode("utf-8"))
            # If found then break
            if codes:
                break

    # Try reduced (2x) image with standart threshold
    if not codes:
        f = cv2.imread(file_name, cv2.IMREAD_REDUCED_GRAYSCALE_2)
        threshold, threshold_image = cv2.threshold(f, 127, 255, 0)
        barcodes = decode(threshold_image, symbols=[64])
        logging.debug("find_QR try reduced 2x image")
        logging.debug(f"find_QR detected: {barcodes}")
        # Check if exactly one code scanned
        codes = []
        for barcode in barcodes:
            codes.append(barcode.data.decode("utf-8"))

    # Try reduced (4x) image with standart threshold
    if not codes:
        f = cv2.imread(file_name, cv2.IMREAD_REDUCED_GRAYSCALE_4)
        threshold, threshold_image = cv2.threshold(f, 127, 255, 0)
        barcodes = decode(threshold_image, symbols=[64])
        logging.debug("find_QR try reduced 4x image")
        logging.debug(f"find_QR detected: {barcodes}")
        # Check if exactly one code scanned
        codes = []
        for barcode in barcodes:
            codes.append(barcode.data.decode("utf-8"))

    # If 0 code scanned
    if len(set(codes)) == 0:
        return None
    # If more than 1 code scanned
    if len(set(codes)) > 1:
        return False
    return codes[0]


async def try_passive_auth(message, state):
    # Get user data from database
    user_data = await state.get_data()
    logging.debug(f"try_passive_auth started for: {message.from_user.id}")
    # Check timestamp of last manual login
    # If delta timestamp > hours_to_relogin then login manually and delete user data
    login_timestamp = user_data.get("login_timestamp", None)
    logging.debug(f"Last mamual login of {message.from_user.id}: {login_timestamp}")
    now = datetime.now().timestamp()
    logging.debug(f"Now: {now}")
    if login_timestamp and hours_to_relogin:
        # 60 minutes * 60 seconds = 3600 seconds in a hour
        if now - login_timestamp > hours_to_relogin * 3600:
            logging.debug(f"Login session closed for {message.from_user.id} due to {hours_to_relogin} hours passed")
            await state.reset_data()
            return None
    # Check if there are email and password
    email = user_data.get("email", None)
    password = user_data.get("password", None)
    # If email and password saved
    if email and password:
        account = {"email": email, "password": password}
        logging.debug(f"Email and password restored from database for {message.from_user.id}")
        # Login
        auth = requests.post(server_path + "/api/v1/auth/sign-in", json=account, timeout=20)
        logging.debug(f"Try to relogin {message.from_user.id}: response {auth.status_code}")
        # 200 means OK
        if auth.status_code == 200:
            # Update cookie
            cookies = auth.cookies
            a = [{"version": c.version, "name": c.name, "value": c.value, "port": c.port,
                "domain": c.domain, "path": c.path, "secure": c.secure, "expires": c.expires,
                "discard": c.discard, "comment": c.comment, "comment_url": c.comment_url,
                "rest": c._rest, "rfc2109": c.rfc2109} for c in cookies]
            user_data["cookie"] = a[0]
            logging.debug(f"Cookie saved for {message.from_user.id}")
            await state.update_data(data=user_data)
            return auth.status_code
        # 503 means Server Unavaliable
        elif auth.status_code == 503:
            return auth.status_code
        # Other Server status means something is wrong
        # Delete remembered email and password
        logging.debug(f"Saved data reset for {message.from_user.id}")
        await state.reset_data()
        return auth.status_code
    # If email and password not saved asks for them
    logging.debug(f"Email and password not found for {message.from_user.id}")
    return None

# ------------------------------------------------------------

@dp.message_handler(commands=["help"], state="*")
async def send_welcome(message: types.Message, state: FSMContext):
    """
    This handler will be called when user sends `/help` command
    """
    prom_message_counter.inc()
    # If not authorized, try to auth
    if await state.get_state() not in ["UserState:authorized", "UserState:choose_controller", "UserState:upload_photos"]:
        message_text = "Вы не авторизованы, используйте команду /start"
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    # Send help-message
    message_text = "Сначала выберите ШУНО к которым подключен светильник\n\
        \n\
        Затем пришлите фото в виде файла\n\
        Фото должно содержать метку о геолокации и четкое изображение QR-кода\n\
        \n\
        Используйте команду /exit для выхода из аккаунта\n\
        При этом пароль будет удален из памяти\n\
        \n\
        Для смены ШУНО воспользуйтесь кнопкой бота".replace("    ", "")
    await message.reply(message_text)
    return


@dp.message_handler(commands=["start"], state="*")
async def send_start(message: types.Message, state: FSMContext):
    """
    Handler checks auth status
    If user entered login-password once, bot tries auth with that data automatically
    """
    prom_message_counter.inc()
    # Check user existance in database
    if await state.get_state() == None:
        await UserState.unauthorized.set()
    user_data = await state.get_data()
    email = user_data.get("email", None)
    # If user already authorized - quit
    if await state.get_state() in ["UserState:authorized", "UserState:choose_controller", "UserState:upload_photos"]:
        message_text = f"Вы авторизованы как {email}\n\
            Используйте команду /exit для выхода из аккаунта\n\
            При этом пароль будет удален из памяти\n\
            \n\
            Перед отправкой фотографий выберите ШУНО".replace("    ", "")
        await message.reply(message_text)
        return
    # Try auth user from database saved login and password
    status = await try_passive_auth(message, state)
    if status == 200:
        prom_successful_auto_relogin.inc()
        logging.debug(f"User {message.from_user.id} logged via try_passive_auth")
        message_text = f"Вы авторизованы как {email}\n\
            Используйте команду /exit для выхода из аккаунта\n\
            При этом пароль будет удален из памяти\n\
            \n\
            Перед отправкой фотографий выберите ШУНО".replace("    ", "")
        await UserState.authorized.set()
        await message.reply(message_text)
        return
    elif status == 503:
        prom_error_counter.inc()
        prom_error_counter.inc()
        prom_authorization_error.inc()
        prom_server_error.inc()
        logging.error(f"Server responsed 503 while {message.from_user.id} logging via try_passive_auth")
        message_text = "Сервер на данный момент недоступен\n\
            Обработка данных невозможна".replace("    ", "")
        await UserState.unauthorized.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    elif status == 401:
        prom_error_counter.inc()
        prom_authorization_error.inc()
        logging.debug(f"User {message.from_user.id} not logged via try_passive_auth, wrong password")
        message_text = "Сохраненные данные логин/пароль не верны. Введите логин (емаил)"
        await UserState.email.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
    elif status:
        logging.error(f"User {message.from_user.id} not logged via try_passive_auth, response {status}")
        message_text = "Введите логин (емаил)"
        await UserState.email.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
    else:
        message_text = "Введите логин (емаил)"
        await UserState.email.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
    return


@dp.message_handler(commands=["exit"], state=[UserState.authorized, UserState.choose_controller, UserState.upload_photos])
async def del_login(message: types.Message, state: FSMContext):
    """
    Handler deletes user email and password from database and un-login user
    """
    prom_message_counter.inc()
    # Reset cookie on server
    user_data = await state.get_data()
    cookie = user_data.get("cookie", {})
    cookie = cookie.copy()
    name = cookie.pop("name", None)
    value = cookie.pop("value", None)
    cookie = requests.cookies.create_cookie(name=name, value=value, **cookie)
    s = requests.session()
    s.cookies.set_cookie(cookie)
    cookie = s.cookies
    s.close()
    requests.post(server_path + "/api/v1/auth/sign-out", cookies=cookie, timeout=20)
    # Unauthorize user
    await UserState.unauthorized.set()
    # Delete user info from database
    await state.reset_data()
    logging.debug(f"User {message.from_user.id} exited. User data deleted")
    message_text = "Вы вышли из системы"
    await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
    return


@dp.message_handler(content_types=["text"], state=[UserState.email])
async def get_email(message: types.Message, state: FSMContext):
    """
    Handler gets email from user message
    """
    prom_message_counter.inc()
    # Email validation
    email = message.text.lower()
    regex = r"^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"
    if(re.search(regex, email)):
        message_text = "Теперь введите пароль"
        # Update user email in databese
        user_data = dict()
        user_data["email"] = email
        await state.update_data(data=user_data)
        logging.debug(f"Email recieved from {message.from_user.id} saved")
        # Change user state
        await UserState.password.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    # If email not valid
    logging.debug(f"Email recieved from {message.from_user.id} not valid")
    message_text = "Неверный емаил! Повторите попытку"
    await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
    return


@dp.message_handler(content_types=["text"], state=[UserState.password])
async def get_password(message: types.Message, state: FSMContext):
    """
    Handler gets password from user message and tries to login
    """
    prom_message_counter.inc()
    password = message.text
    await bot.delete_message(message.chat.id, message.message_id)
    user_data = await state.get_data()
    user_data["password"] = password
    email = user_data.get("email", None)
    account = {"email": email, "password": password}
    # Login
    auth = requests.post(server_path + "/api/v1/auth/sign-in", json=account, timeout=20)
    # 200 means OK
    if auth.status_code == 200:
        # Update cookie
        cookies = auth.cookies
        a = [{"version": c.version, "name": c.name, "value": c.value, "port": c.port,
            "domain": c.domain, "path": c.path, "secure": c.secure, "expires": c.expires,
            "discard": c.discard, "comment": c.comment, "comment_url": c.comment_url,
            "rest": c._rest, "rfc2109": c.rfc2109} for c in cookies]
        user_data["cookie"] = a[0]
        # Update timestamp of manual login
        login_timestamp = datetime.now().timestamp()
        user_data["login_timestamp"] = login_timestamp
        # Save login and password for future authorization
        await state.update_data(data=user_data)
        # Change user state
        prom_successful_manual_login.inc()
        await UserState.authorized.set()
        logging.debug(f"User {message.from_user.id} login as {email} at time: {login_timestamp}")
        logging.debug(f"Cookie saved for {message.from_user.id}")
        message_text = f"Вы авторизованы как {email}\n\
            Используйте команду /exit для выхода\n\
            При этом пароль будет удален из памяти\n\
            \n\
            Перед отправкой фотографий выберите ШУНО".replace("    ", "")
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        await message.answer(message_text, reply_markup=keyboard)
        return
    # 503 means Server Unavaliable
    elif auth.status_code == 503:
        prom_error_counter.inc()
        prom_authorization_error.inc()
        # Save login and password for future authorization
        await state.update_data(data=user_data)
        # Change user state
        prom_error_counter.inc()
        prom_error_counter.inc()
        prom_authorization_error.inc()
        prom_server_error.inc()
        logging.debug(f"User {message.from_user.id} {email} and password saved")
        logging.error(f"Server responsed 503 while {message.from_user.id} logging via manual login")
        message_text = "Сервер на данный момент недоступен\n\
            Обработка данных невозможна".replace("    ", "")
        await UserState.unauthorized.set()
        await message.answer(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    elif auth.status_code == 401:
        prom_error_counter.inc()
        prom_authorization_error.inc()
        await state.reset_data()
        await UserState.email.set()
        logging.debug(f"User {message.from_user.id} provided wrong email and/or password")
        message_text = "Неверный логин и/или пароль, введите логин (емаил) еще раз"
        await message.answer(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    # Other Server status means something went wrong
    prom_error_counter.inc()
    prom_error_counter.inc()
    prom_authorization_error.inc()
    prom_server_error.inc()
    message_text = "Авторизация не удалась, введите логин (емаил) еще раз"
    logging.error(f"Server responsed {auth.status_code} while {message.from_user.id} logging via manual login")
    # Delete remembered email and password
    await state.reset_data()
    await UserState.email.set()
    await message.answer(message_text, reply_markup=types.ReplyKeyboardRemove())
    return


@dp.callback_query_handler(lambda c: c.data == "get_list", state=[UserState.authorized, UserState.upload_photos])
async def get_controller_list(callback_query: types.CallbackQuery, state: FSMContext):
    """
    Handler gets controller list
    """
    prom_get_list_counter.inc()
    message = callback_query.message
    await bot.answer_callback_query(callback_query.id)
    # Check user authorization with empty request
    user_data = await state.get_data()
    cookie = user_data.get("cookie", {})
    cookie = cookie.copy()
    name = cookie.pop("name", None)
    value = cookie.pop("value", None)
    cookie = requests.cookies.create_cookie(name=name, value=value, **cookie)
    s = requests.session()
    s.cookies.set_cookie(cookie)
    cookie = s.cookies
    s.close()
    add = requests.get(server_path + "/api/v1/auth/check", cookies=cookie, timeout=20)
    # If unauthorized
    if add.status_code == 401:
        # Try auth user from database saved login and password
        status = try_passive_auth(message, state)
        # If auth is successful
        if status == 200:
            prom_successful_auto_relogin.inc()
            await UserState.authorized.set()
        elif status == 503:
            prom_error_counter.inc()
            prom_error_counter.inc()
            prom_authorization_error.inc()
            prom_server_error.inc()
            message_text = "Сервер на данный момент недоступен\n\
                Обработка данных невозможна".replace("    ", "")
            await UserState.unauthorized.set()
            logging.debug(f"User {message.from_user.id} unlogined")
            logging.error(f"Server responsed 503 while {message.from_user.id} logging via try_passive_auth")
            await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
        elif status == 401:
            prom_error_counter.inc()
            prom_authorization_error.inc()
            await state.reset_data()
            await UserState.email.set()
            logging.debug(f"User {message.from_user.id} provided wrong email and/or password")
            message_text = "Неверный логин и/или пароль, введите логин (емаил) еще раз"
            await message.answer(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
        elif status:
            prom_error_counter.inc()
            prom_authorization_error.inc()
            logging.error(f"Server responsed {status} while {message.from_user.id} logging via try_passive_auth")
            message_text = "Авторизация не удалась, введите логин (емаил)"
            await UserState.email.set()
            await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
        else:
            prom_error_counter.inc()
            prom_authorization_error.inc()
            message_text = "Авторизация не удалась, введите логин (емаил)"
            await UserState.email.set()
            await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
    # If 200 then server works normally
    elif add.status_code == 200:
        pass
    # Unknown errors
    else:
        prom_error_counter.inc()
        prom_server_error.inc()
        logging.error(f"Server responsed {add.status_code} while {message.from_user.id} authorization check")
        message_text = "Сервер на данный момент недоступен\n\
            Обработка данных невозможна".replace("    ", "")
        await UserState.unauthorized.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    # Get controller list
    user_data = await state.get_data()
    cookie = user_data.get("cookie", {})
    cookie = cookie.copy()
    name = cookie.pop("name", None)
    value = cookie.pop("value", None)
    cookie = requests.cookies.create_cookie(name=name, value=value, **cookie)
    s = requests.session()
    s.cookies.set_cookie(cookie)
    cookie = s.cookies
    s.close()
    add = requests.get(server_path + "/api/v1/telegram/controller/list", cookies=cookie, timeout=20)
    logging.debug(f"User {message.from_user.id} recieved controller list. Response {add.status_code}")
    # Check server response
    if add.status_code == 200:
        # Get info
        controllers = add.json()
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        user_data["controllers"] = {}
        for iterator, controller in enumerate(controllers):
            keyboard.add(types.InlineKeyboardButton(text=controller["name"], callback_data="c" + str(iterator)))
            user_data["controllers"]["c" + str(iterator)] = (controller["name"], controller["id"])
        await state.update_data(data=user_data)
        message_text = "Выберите шкаф:"
        await UserState.choose_controller.set()
        await message.answer(message_text, reply_markup=keyboard)
        return
    elif add.status_code == 401:
        prom_error_counter.inc()
        prom_controllers_get_error.inc()
        message_text = "Вы не авторизованы, используйте команду /start"
        await UserState.unauthorized.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    else:
        prom_error_counter.inc()
        prom_error_counter.inc()
        prom_server_error.inc()
        prom_controllers_get_error.inc()
        logging.error(f"User {message.from_user.id} not recieved controller list. Response {add.status_code}")
        message_text = "Отправка данных не удалась\n\
            Причина неизвестна".replace("    ", "")
        await message.reply(message_text)
    return


@dp.callback_query_handler(lambda c: c.data == "get_list", state=[UserState.choose_controller])
async def controller_list_gotten(callback_query: types.CallbackQuery, state: FSMContext):
    """
    Handler do nothing because controller list already sent
    """
    prom_get_list_counter.inc()
    message = callback_query.message
    logging.debug(f"User {message.from_user.id} already recieved controller list")
    await bot.answer_callback_query(callback_query.id)
    return


@dp.callback_query_handler(lambda c: c.data == "get_list", state="*")
async def controller_list_auth(callback_query: types.CallbackQuery, state: FSMContext):
    """
    Handler do nothing because controller list already sent
    """
    prom_get_list_counter.inc()
    prom_error_counter.inc()
    prom_authorization_error.inc()
    message = callback_query.message
    logging.debug(f"User {message.from_user.id} can't get controller list, not authorized")
    message_text = "Вы не авторизованы, используйте команду /start"
    await UserState.unauthorized.set()
    await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
    return


@dp.callback_query_handler(lambda c: c.data[0] == "c", state=[UserState.choose_controller])
async def set_controller(callback_query: types.CallbackQuery, state: FSMContext):
    """
    Handler checks choosen controller and get prepaired for photo recieving
    """
    prom_get_controller_counter.inc()
    message = callback_query.message
    await bot.answer_callback_query(callback_query.id)
    # Save the chosen controller
    user_data = await state.get_data()
    controllers = user_data.get("controllers", {})
    user_data["controllers"] = {}
    controllers = controllers.get(callback_query.data, None)
    user_data["controller_name"] = controllers[0]
    user_data["controller_id"] = controllers[1]
    await state.update_data(data=user_data)
    if controllers:
        await UserState.upload_photos.set()
        logging.debug(f"User {message.from_user.id} choose controller {controllers[0]}")
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controllers[0]}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await bot.delete_message(chat_id=callback_query.message.chat.id, message_id=callback_query.message.message_id)
        await message.answer(message_text, reply_markup=keyboard)
        return
    else:
        await UserState.authorized.set()
        logging.debug(f"User {message.from_user.id} choose controller from old data")
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = "Выбран шкаф из старых данных\n\
            Пожалуйста, загрузите новый список используя кнопку ниже".replace("    ", "")
        await bot.delete_message(chat_id=callback_query.message.chat.id, message_id=callback_query.message.message_id)
        await message.answer(message_text, reply_markup=keyboard)
        return


@dp.callback_query_handler(lambda c: c.data[0] == "c", state="*")
async def set_controller_wrong_state(callback_query: types.CallbackQuery, state: FSMContext):
    """
    Handler checks choosen controller and get prepaired for photo recieving
    """
    prom_get_controller_counter.inc()
    message = callback_query.message
    await bot.answer_callback_query(callback_query.id)
    # Drop error because user now not choosing controller
    logging.debug(f"User {message.from_user.id} choose controller from wrong state")
    keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
    keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
    message_text = "Выбран шкаф из старых данных\n\
        Пожалуйста, загрузите новый список используя кнопку ниже".replace("    ", "")
    await bot.delete_message(chat_id=callback_query.message.chat.id, message_id=callback_query.message.message_id)
    await message.answer(message_text, reply_markup=keyboard)
    return


@dp.message_handler(content_types=["document"], state=[UserState.upload_photos])
async def scan_image(message: types.Document, state: FSMContext):
    """
    This handler processes images
    """
    prom_message_counter.inc()
    # Check user authorization with empty request
    user_data = await state.get_data()
    cookie = user_data.get("cookie", {})
    cookie = cookie.copy()
    name = cookie.pop("name", None)
    value = cookie.pop("value", None)
    cookie = requests.cookies.create_cookie(name=name, value=value, **cookie)
    s = requests.session()
    s.cookies.set_cookie(cookie)
    cookie = s.cookies
    s.close()
    logging.debug(f"File recieved from {message.from_user.id}")
    add = requests.get(server_path + "/api/v1/auth/check", cookies=cookie, timeout=20)
    # If unauthorized
    if add.status_code == 401:
        # Try auth user from database saved login and password
        status = try_passive_auth(message, state)
        # If auth is successful
        if status == 200:
            prom_successful_auto_relogin.inc()
            await UserState.upload_photos.set()
        elif status == 503:
            prom_error_counter.inc()
            prom_error_counter.inc()
            prom_authorization_error.inc()
            prom_server_error.inc()
            logging.debug(f"User {message.from_user.id} unlogined")
            logging.error(f"Server responsed 503 while {message.from_user.id} logging via try_passive_auth")
            message_text = "Сервер на данный момент недоступен\n\
                Обработка данных невозможна".replace("    ", "")
            await UserState.unauthorized.set()
            await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
        elif status == 401:
            prom_error_counter.inc()
            prom_authorization_error.inc()
            await state.reset_data()
            await UserState.email.set()
            logging.debug(f"User {message.from_user.id} provided wrong email and/or password")
            message_text = "Неверный логин и/или пароль, введите логин (емаил) еще раз"
            await message.answer(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
        elif status:
            logging.error(f"Server responsed {status} while {message.from_user.id} logging via try_passive_auth")
            message_text = "Авторизация не удалась, введите логин (емаил)"
            await UserState.email.set()
            await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
        else:
            message_text = "Авторизация не удалась, введите логин (емаил)"
            await UserState.email.set()
            await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
            return
    # If 200 then server works normally
    elif add.status_code == 200:
        pass

    # Unknown errors
    else:
        prom_error_counter.inc()
        prom_server_error.inc()
        logging.error(f"Server responsed {add.status_code} while {message.from_user.id} authorization check")
        message_text = "Сервер на данный момент недоступен\n\
            Обработка данных невозможна".replace("    ", "")
        await UserState.unauthorized.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
        return

    # Check the document format
    if not (
        message.document.mime_type == "image/jpeg" and (
        message.document.file_name[-5:].lower() == ".jpeg" or
        message.document.file_name[-4:].lower() == ".jpg")
        ):
        prom_error_counter.inc()
        prom_wrong_filetype_error.inc()
        logging.debug(f"User {message.from_user.id} uploaded wrong document format: {message.document.mime_type}")
        message_text = "Загрузите файл формата .jpeg или .jpg"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return

    # Check the document size
    if message.document.file_size >= allowed_size*1024*1024:
        prom_error_counter.inc()
        prom_wrong_filesize_error.inc()
        logging.debug(f"User {message.from_user.id} uploaded document larger {allowed_size} MB")
        message_text = f"Размер файла должен быть менее {allowed_size} MB"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return

    # Get file's meta-info
    file_info = await bot.get_file(message.document.file_id)
    # Download file
    try:
        f = requests.get(f"https://api.telegram.org/file/bot{API_TOKEN}/{file_info.file_path}", timeout=20)
    except Exception as e:
        prom_telegram_exeption_error.inc()
        logging.error(f"Failed to get file info from user_id ({message.from_user.id}/{message.from_user.username}) due to Telegram API error")
        logging.error(str(e))
        message_text = "Не удалось получить информацию о документе. Попробуйте снова позднее"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return
    logging.debug(f"Successfully get info about file from {message.from_user.id}")

    # If 200 then server works normally
    if f.status_code == 200:
        pass
    else:
        prom_telegram_exeption_error.inc()
        logging.error(f"Failed to get file info from user_id ({message.from_user.id}/{message.from_user.username}) due to Telegram API error. Status code: {f.status_code}")
        message_text = "Не удалось получить информацию о документе. Попробуйте снова позднее"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return

    # Try to save file on disk
    file_name = message.document.file_name
    try:
        open(save_dir + "/" + file_name, "wb").write(f.content)
    except Exception as e:
        prom_file_download_error.inc()
        logging.error(f"Failed to save file from user_id ({message.from_user.id}/{message.from_user.username}) to disk")
        logging.error(str(e))
        message_text = "Не удалось сохранить Ваш документ. Попробуйте снова позднее"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return
    logging.debug(f"File from {message.from_user.id} successfully opened")

    # Extract GPS
    latitude, longitude = find_GPS(save_dir + "/" + file_name)
    if latitude == None or longitude == None:
        remove(save_dir + "/" + file_name)
        prom_error_counter.inc()
        prom_no_gps_error.inc()
        logging.debug(f"No GPS found in file from {message.from_user.id}")
        message_text = "Не удалось найти данные о геолокации"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return

    # Extract QR-code and delete file
    qr_data = find_QR(save_dir + "/" + file_name)
    remove(save_dir + "/" + file_name)
    if qr_data == None:
        prom_error_counter.inc()
        prom_no_qr_error.inc()
        logging.debug(f"No QR-data found in file from {message.from_user.id}")
        message_text = "Не удалось прочитать QR-код"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return

    if qr_data == False:
        logging.debug(f"More than one QR-data found in file from {message.from_user.id}")
        message_text = "Распознано более одного QR-кода"
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return

    # Collect info for server
    user_data = await state.get_data()
    controller_id = user_data.get("controller_id", None)
    controller_name = user_data.get("controller_name", None)
    light = {"qrData": qr_data, "controllerId": controller_id,
         "latitude": latitude, "longitude": longitude}
    logging.debug(f"Data extracted from file from {message.from_user.id}")

    # Get cookie
    cookie = user_data.get("cookie", {})
    cookie = cookie.copy()
    name = cookie.pop("name", None)
    value = cookie.pop("value", None)
    cookie = requests.cookies.create_cookie(name=name, value=value, **cookie)
    s = requests.session()
    s.cookies.set_cookie(cookie)
    cookie = s.cookies
    s.close()

    # Make request to post light
    add = requests.post(server_path + "/api/v1/telegram/lamp/lora/create", json=light, cookies=cookie, timeout=20)

    # Check server response
    if add.status_code == 200:
        # Return scanned info
        prom_light_added.inc()
        logging.debug(f"Data send from file from {message.from_user.id}")
        message_text = f"Данные успешно обработаны:\n\
            Шкаф: {controller_name}\n\
            Широта: {latitude}\n\
            Долгота: {longitude}\n\
            QR-код: {qr_data}\n\
            ".replace("    ", "")
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
        return
    elif add.status_code == 401:
        prom_error_counter.inc()
        prom_authorization_error.inc()
        logging.debug(f"Data from file from {message.from_user.id} not send, authorization error")
        message_text = "Вы не авторизованы, используйте команду /start"
        await UserState.unauthorized.set()
        await message.reply(message_text, reply_markup=types.ReplyKeyboardRemove())
        return
    else:
        prom_error_counter.inc()
        prom_server_error.inc()
        logging.error(f"Server responsed {status} while {message.from_user.id} send QR-file")
        message_text = "Отправка данных не удалась\n\
            Причина неизвестна".replace("    ", "")
        await message.reply(message_text)
        # Send new button
        controller_name = user_data.get("controller_name", None)
        keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
        keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
        message_text = f"Выбран шкаф \"{controller_name}\"\n\
            Можете загружать фото QR-кодов принадлежащих этому шкафу\n\
            Для смены шкафа используйте кнопку ниже".replace("    ", "")
        await message.answer(message_text, reply_markup=keyboard)
    return


@dp.message_handler(content_types=["document"], state=[UserState.authorized, UserState.choose_controller])
async def doc_without_controller(message: types.message):
    """
    This handler will be called on all other messages while auth
    """
    prom_message_counter.inc()
    # Warn user about controller choosing
    await UserState.authorized.set()
    logging.debug(f"User {message.from_user.id} sent document without choosing controller")
    message_text = "Перед отправкой фотографий выберите ШУНО".replace("    ", "")
    keyboard = types.InlineKeyboardMarkup(resize_keyboard=True, row_width=1)
    keyboard.add(types.InlineKeyboardButton(text="Получить список ШУНО", callback_data="get_list"))
    await message.reply(message_text, reply_markup=keyboard)
    return


@dp.message_handler(content_types=content_types, state="*")
async def all_msg(message: types.message):
    """
    This handler will be called on all other messages
    """
    prom_message_counter.inc()
    # Warn user about help option
    logging.debug(f"User {message.from_user.id} sent unsupported data")
    message_text = "Неизвестные данные\n\
        Используйте команду /help".replace("    ", "")
    await message.reply(message_text)
    return

# ------------------------------------------------------------

@dp.errors_handler(exception=TelegramAPIError)
async def errors_handler(update, error):
    """
    Collect all available exceptions from Telegram
    """
    prom_error_counter.inc()
    prom_telegram_exeption_error.inc()
    # Collect some info about an exception and write to file
    error_msg = f"Exception of type {type(error)}. Chat ID: {update.message.chat.id}. " \
                f"User ID: {update.message.from_user.id}. Error: {error}"
    logging.error(error_msg)
    return True

# ------------------------------------------------------------

async def on_startup(dp):
    """
    Execute this code when startup
    Saves command list for bot
    """
    logging.info("Setting commands...")
    commands = [types.BotCommand(command="/help", description="Помощь"),
                types.BotCommand(command="/start", description="Начать работу")]
    await bot.set_my_commands(commands)
    logging.info("Commands are set for bot")


async def on_shutdown(dp):
    """
    Execute this code when shutdown
    Very important! Saves database of FMS (finite state mechine)
    """
    logging.warning("Shutting down database...")
    await dp.storage.close()
    await dp.storage.wait_closed()
    logging.warning("Database closed")

# ------------------------------------------------------------

# Start polling
if __name__ == "__main__":
    start_http_server(metrics_port)
    executor.start_polling(dp, timeout=20, on_startup=on_startup, on_shutdown=on_shutdown)
