# -*- coding: utf-8 -*-
from __future__ import unicode_literals, division

__doc__ = """
@since: 09.08.14
@author: yokotoka
@contact: <yokotoka@gmail.com>
"""
__author__ = 'yokotoka'


from instagram.client import InstagramAPI
from settings import CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, USERNAME, PASSWORD
from instagram.automation import get_access_token_by_credentials
import time
import sys


SCOPE = ["basic", "comments", "relationships", "likes"]

GRAB_COOKIE = '/tmp/instabot.cookie.'+str(time.time())+'.txt'

api = InstagramAPI(client_id=CLIENT_ID, client_secret=CLIENT_SECRET, redirect_uri=REDIRECT_URI)
access_token = get_access_token_by_credentials(api, USERNAME, PASSWORD, SCOPE, GRAB_COOKIE)
print "ACCESS_TOKEN={}".format(access_token)



