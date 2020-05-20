import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.templating import Jinja2Templates
import hashlib
from random import randint
from app.database import MongodbService
import datetime

BASE_FOLDER = os.path.dirname(os.path.abspath(__file__))
RESOURCE_DIR = os.path.join(BASE_FOLDER, 'web_layout')

app = FastAPI()

templates = Jinja2Templates(directory=RESOURCE_DIR)

database = MongodbService.get_instance()


@app.get("/")
async def read_index(request: Request):
    return templates.TemplateResponse("generate.html", {"request": request})


@app.get('/generate/')
async def generate(request: Request, secret: str, passphrase: str, lifetime: str):

    """

    This function is used for generating of secret key for your secret message.

    :param secret:

            Input your secret message (String).

    :param passphrase:

            Input a word or phrase which will be used for access to your secret message (String).

    :param lifetime:

            Input life time of your message in seconds (Integer).
            After inputted time expiration the message will delete automatically.

    :return:

            After script execution the secret key will be returned.

    """

    if not lifetime.isdigit():
        return {
            'secret_key': '',
            'msg': 'You input incorrect lifetime, it should be an integer.'
        }
    random_range = randint(1, 39), randint(1, 39)
    while random_range[0] == random_range[1]:
        random_range = randint(1, 39), randint(1, 39)
    encrypted_passphrase = hashlib.sha1(passphrase.encode('utf8')).hexdigest()
    encrypted_secret = hashlib.sha1(secret.encode('utf8')).hexdigest()
    secret_key = hashlib.sha1(encrypted_secret[min(random_range): max(random_range)].encode('utf8')).hexdigest()
    inputted_data = {
        'secret': secret,
        'passphrase': encrypted_passphrase,
        'secret_key': secret_key[13:7:-1],
        'expired_at': datetime.datetime.utcnow() + datetime.timedelta(seconds=int(lifetime))
    }
    database.save_data(secret=inputted_data)
    return {
        'secret_key': f'Your secret link is: {request.base_url}secrets/{inputted_data["secret_key"]}',
        'msg': ''
    }


@app.get("/secrets/{secret_key}")
async def check(request: Request, secret_key: str):

    """

    This function checks inputted secret key.

    :param secret_key:

        Input the secret key provided for your secret message (String).

    :return:

        If inputted secret key is correct, you will be redirected on page for receiving of secret message.

    """

    extracted_data = database.get_data(secret_key=secret_key)
    if not extracted_data:
        return templates.TemplateResponse("check.html", {"request": request})
    else:
        return templates.TemplateResponse("receive.html", {"request": request})


@app.get("/receive/")
async def receive(secret_key: str, passphrase: str):

    """

    This function is used for receiving of secret message.

    :param secret_key:

        The secret key will be automatically taken from previous page.

    :param passphrase:

        Input the passphrase you guessed for your secret message (String).

    :return:

        After script execution the secret message will be returned.

    """

    current_secret_key = secret_key[secret_key.rfind("/") + 1:]
    extracted_data = database.get_data(secret_key=current_secret_key)
    if not extracted_data:
        return {
            'secret': '',
            'msg': 'secret has already been viewed.'
        }
    elif extracted_data['passphrase'] == hashlib.sha1(passphrase.encode('utf8')).hexdigest():
        secret = database.get_and_delete_data(secret_key=current_secret_key)['secret']
        return {
            'secret': f'This message is for you: {secret}',
            'msg': 'careful: we will only show it once.'
        }
    else:
        return {
            'secret': 'You input incorrect passphrase, please try again.',
            'msg': ''
        }
