import os
from time import sleep

from vncdotool import api

if __name__ == '__main__':
    ip = os.environ.get('IP')
    port = os.environ.get('PORT')
    user = os.environ.get('USERNAME')
    pw = os.environ.get('PASSWORD')
    client = api.connect(f"{ip}::{port}", username=user, password=pw)
    sleep(0.1)
    client.disconnect()
