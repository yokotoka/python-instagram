# -*- coding: utf-8 -*-
from __future__ import unicode_literals, division

__doc__ = """
@since: 09.08.14
@author: yokotoka
@contact: <yokotoka@gmail.com>
"""
__author__ = 'yokotoka'


from grab import Grab
import os
import re

import logging
log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


RE_ACCESS_TOKEN = re.compile('Location.+\?code=([A-Za-z0-9]+)')


class InvalidUsernameOrPasswordError(Exception):pass
class UnknownException(Exception): pass
class TokenExtractError(Exception):pass

def get_access_token_by_credentials(api, username, password, scope, cookie_file=None):
    redirect_uri = api.get_authorize_login_url(scope=scope)
    log.debug("Redirect URI: {}".format(redirect_uri))
    if not os.path.exists(os.path.dirname(cookie_file)):
        os.makedirs(os.path.dirname(cookie_file))
    if not os.path.exists(cookie_file):
        with open(cookie_file, 'w'):
            pass
    grab = Grab()
    grab.setup(
        cookiefile=cookie_file,
        debug_post=True,
        #follow_location=False,
        log_dir='.'
    )
    log.debug('Make request to redirect URI...')
    instagram_oauth_open_resp = grab.go(redirect_uri)
    #import IPython; IPython.embed()
    grab.set_input('username', username)
    grab.set_input('password', password)
    instagram_oauth_post_login_resp = grab.submit()
    #if instagram_oauth_open_resp.headers.has_key('Location'):
    #    instagram_oauth_maybe_token_resp = grab.go(instagram_oauth_open_resp.headers['Location'])
    #else:
        #grab.setup(follow_location=True)

    if "Please enter a correct username and password" in instagram_oauth_post_login_resp.unicode_body():
        raise InvalidUsernameOrPasswordError("username={}, password=******".format(username))
    log.debug('Credentials is OK...')
    if not "oauth/authorize" in instagram_oauth_post_login_resp.url:
        log.debug("{}\n{}\n{}".fomrat(instagram_oauth_post_login_resp.url, instagram_oauth_post_login_resp.head, instagram_oauth_post_login_resp.unicode_body()))
        raise UnknownException('Not redirected on OAuth APPROVE REQUEST window, last url is: {}'.format(instagram_oauth_post_login_resp.url))
    log.debug('Approve request form is FOUND...')
    grab.set_input('allow', 'Authorize')
    grab.setup(follow_location=False)
    log.debug('Sending "Yes, we approve" request...')
    instagram_oauth_maybe_token_resp = grab.submit(submit_name='allow', extra_post=dict(allow='Authorize'))
    maybe_code_list = re.findall(RE_ACCESS_TOKEN, instagram_oauth_maybe_token_resp.head)
    if not maybe_code_list:
        raise TokenExtractError("Can't extract code from headers:\n\n{}".format(instagram_oauth_maybe_token_resp.head))
    if len(maybe_code_list) > 1:
        raise TokenExtractError("Can't know, what is code: {}".fromat(maybe_code_list))
    log.debug('Access code is extracted!')
    access_code, = maybe_code_list
    log.debug('Access code = [{}]'.format(access_code))
    access_token = api.exchange_code_for_access_token(access_code)
    log.debug('ACCESS_TOKEN=[{}]'.format(access_token))
    return access_token


    #import IPython; IPython.embed()
