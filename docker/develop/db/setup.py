from pymongo import MongoClient
from collections import OrderedDict
from json import loads, dumps


client = MongoClient('localhost', 27017)
client.users.add_user('admin', 'password', roles=[{'role':'userAdminAnyDatabase', 'db':'admin'}])

