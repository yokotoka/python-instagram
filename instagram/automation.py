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
import time
import logging
log = logging.getLogger(__file__)
log.addHandler(logging.StreamHandler())
log.setLevel(logging.DEBUG)


RE_EXCHANGE_CODE = re.compile('.+code=([A-Za-z0-9]+).*')



class InvalidUsernameOrPasswordError(Exception):pass
class UnknownException(Exception): pass
class ExchangeCodeExtractError(Exception):pass


def click_yes_iam_authorize_this_app(grab, authorize_form):
    log.debug('Approve request form is FOUND...')
    grab.set_input('allow', 'Authorize')
    log.debug('Sending "Yes, we approve" request...')
    step1_3_submit_authorize_form = grab.submit(submit_name='allow', extra_post=dict(allow='Authorize'))
    time.sleep(3)
    if not step1_3_submit_authorize_form.headers.has_key('Location'):
        raise UnknownException('Not redirect after approve access')
    maybe_code_redirect_location = step1_3_submit_authorize_form.headers['Location']
    if not re.match(RE_EXCHANGE_CODE, maybe_code_redirect_location):
        raise ExchangeCodeExtractError('Not found exchange in Location header: {}'.format(maybe_code_redirect_location))
    return maybe_code_redirect_location



def go_redirect_location(grab, redirect_location):
    if not "/oauth/authorize" in redirect_location:
        raise UnknownException('Redirected, but not in /oauth/authorize url')

    step1_2_redirect_to_authorize = grab.go(redirect_location)
    time.sleep(3)

    if not step1_2_redirect_to_authorize.headers.has_key('Location') and "is requesting to do the following" in step1_2_redirect_to_authorize.unicode_body():
        code_redirect_location = click_yes_iam_authorize_this_app(grab, authorize_form=step1_2_redirect_to_authorize)
        return code_redirect_location
    elif step1_2_redirect_to_authorize.headers.has_key('Location'):
        if re.match(RE_EXCHANGE_CODE, step1_2_redirect_to_authorize.headers['Location']):
            maybe_code_redirect_location = step1_2_redirect_to_authorize.headers['Location']
            return maybe_code_redirect_location
        else:
            UnknownException('Not excepted way 3')
    else:
        raise UnknownException('Not excepted way 2')


def pass_the_login_form(grab, username, password):
    grab.set_input('username', username)
    grab.set_input('password', password)
    step1_1_submit_login_and_pass = grab.submit()
    time.sleep(3)

    if "Please enter a correct username and password" in step1_1_submit_login_and_pass.unicode_body():
        raise InvalidUsernameOrPasswordError("username={}, password=******".format(username))
    log.debug('Credentials is OK...')

    if not step1_1_submit_login_and_pass.headers.has_key('Location'):
        raise UnknownException('Not redirected to /oauth/authorize')

    redirect_location = step1_1_submit_login_and_pass.headers['Location']
    return go_redirect_location(grab, redirect_location)


def get_access_token_by_credentials(api, username, password, scope, grab_setup_opts={}):
    log.debug('Start extracting token...')

    if grab_setup_opts.has_key('cookiefile'):
        cookie_file = grab_setup_opts['cookiefile']
        if not os.path.exists(os.path.dirname(cookie_file)):
            os.makedirs(os.path.dirname(cookie_file))
        if not os.path.exists(cookie_file):
            with open(cookie_file, 'w'):
                pass

    grab = Grab()
    grab.setup(
        #debug_post=True,
        follow_location=False,
        log_dir='.',
        **grab_setup_opts
    )

    redirect_uri = api.get_authorize_login_url(scope=scope)
    log.debug("Redirect URI: {}".format(redirect_uri))

    log.debug('Make request to redirect URI...')
    step1_login = grab.go(redirect_uri)
    time.sleep(3)

    if not step1_login.headers.has_key('Location') and ('username' in step1_login.unicode_body() and 'password' in step1_login.unicode_body()):
        code_redirect_location = pass_the_login_form(grab, username, password)
    elif step1_login.headers.has_key('Location'):
        if "/oauth/authorize" in step1_login.headers['Location']:
            code_redirect_location = go_redirect_location(grab, step1_login.headers['Location'])
        else:
            raise UnknownException('Not excepted way 4')
    else:
        raise UnknownException('Not excepted way 1')

    maybe_code_list = re.findall(RE_EXCHANGE_CODE, code_redirect_location)
    if not maybe_code_list:
        raise ExchangeCodeExtractError("Can't extract code from headers:\n\n{}".format(code_redirect_location))
    if len(maybe_code_list) > 1:
        raise ExchangeCodeExtractError("Can't know, what is code: {}".fromat(maybe_code_list))
    log.debug('Access code is extracted!')
    access_code, = maybe_code_list
    log.debug('Access code = [{}]'.format(access_code))
    access_token = api.exchange_code_for_access_token(access_code)
    time.sleep(3)
    log.debug('ACCESS_TOKEN=[{}]'.format(access_token))
    return access_token
