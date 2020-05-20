# -*- coding: utf-8 -*-

import os
from pymongo import MongoClient, ASCENDING


MONGO_DB_ADDR = os.getenv('MONGO_DB_ADDR', 'localhost')


class MongodbService(object):
    _instance = None
    _client = None
    _db = None

    @classmethod
    def get_instance(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls, *args, **kwargs)
            cls.__init__(cls._instance, *args, **kwargs)
        return cls._instance

    def __init__(self):
        self._client = MongoClient(MONGO_DB_ADDR, 27017)
        self._db = self._client.onetimesecrets
        self._db.secrets.create_index([('expired_at', ASCENDING)], expireAfterSeconds=0)

    def get_data(self, secret_key):
        return self._db.secrets.find_one({'secret_key': secret_key})

    def get_and_delete_data(self, secret_key):
        return self._db.secrets.find_one_and_delete({'secret_key': secret_key})

    def save_data(self, secret):
        self._db.secrets.insert_one(secret)
