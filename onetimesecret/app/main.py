# -*- coding: utf-8 -*-

from fastapi import FastAPI, HTTPException
import hashlib
from random import randint
from app.database import MongodbService
import datetime


app = FastAPI()

database = MongodbService.get_instance()


@app.get('/generate')
async def generate(secret: str, passphrase: str, lifetime: int):

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
        'expired_at': datetime.datetime.utcnow() + datetime.timedelta(seconds=lifetime)
    }
    database.save_data(secret=inputted_data)
    return {'secret_key': inputted_data['secret_key']}


subapi = FastAPI(openapi_prefix='/secrets')


@subapi.get('/{secret_key}')
async def check(secret_key: str, passphrase: str):

    """

    This function is used for receiving of secret message.

    :param secret_key:

            Input the secret key provided for your secret message (String).

    :param passphrase:

            Input the passphrase you guessed for your secret message (String).

    :return:

            After script execution the secret message will be returned.

    """

    extracted_data = database.get_data(secret_key=secret_key)
    if not extracted_data:
        raise HTTPException(status_code=404, detail='Incorrect secret key, please try again.')
    if extracted_data['passphrase'] == hashlib.sha1(passphrase.encode('utf8')).hexdigest():
        secret = extracted_data['secret']
        return {'secret': secret}
    else:
        raise HTTPException(status_code=404,
                            detail=f'Incorrect passphrase, please try again.')


app.mount('/secrets', subapi)
