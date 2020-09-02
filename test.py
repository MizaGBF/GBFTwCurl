import time
import pycurl
import json
import certifi
from datetime import datetime, timedelta
from urllib.parse import urlencode
from io import BytesIO
import requests
from requests_oauthlib import OAuth1, OAuth1Session
from requests import models
import signal
import webbrowser

class Stream():
    def __init__(self, keys):
        self.keys = keys
        self.track = {'track': " :参戦ID\n参加者募集！\n, :Battle ID\nI need backup!\nLvl"}
        self.url = 'https://stream.twitter.com/1.1/statuses/filter.json?' + urlencode(self.track)
        self.request_token = {}
        self.oauth = OAuth1Session(self.keys['consumer_key'], client_secret=self.keys['consumer_secret'])
        self.conn = None
        self.buffer = b''
        self.running = True

        signal.signal(signal.SIGINT, self.ctrlC)

    def ctrlC(self, sig, frame):
        self.running = False
        raise Exception()

    def authentificate_web():
        webbrowser.open(self.get_auth_url(), new=2)
        pin = input()
        t = self.get_access_token(pin)
        print("Access tokens:", t)
        return t

    def _get_oauth_url(self, endpoint):
        return 'https://self.api.twitter.com/oauth/' + endpoint

    def apply_auth(self):
        return OAuth1(self.keys['consumer_key'],
                      client_secret=self.keys['consumer_secret'],
                      resource_owner_key=self.keys['access_token'],
                      resource_owner_secret=self.keys['access_token_secret'],
                      decoding=None)

    def _get_request_token(self, access_type=None):
        try:
            url = self._get_oauth_url('request_token')
            if access_type:
                url += '?x_auth_access_type=%s' % access_type
            return self.oauth.fetch_request_token(url)
        except Exception as e:
            raise e

    def set_access_token(self, key, secret):
        self.keys['access_token'] = key
        self.keys['access_token_secret'] = secret

    def get_authorization_url(self):
        try:
            url = self._get_oauth_url('authorize')
            self.request_token = self._get_request_token(access_type=access_type)
            return self.oauth.authorization_url(url)
        except Exception as e:
            raise e

    def get_auth_url(self): # OK
        url = self._get_oauth_url('authorize')
        self.request_token = self._get_request_token()
        return self.oauth.authorization_url(url)

    def get_access_token(self, verifier=None):
        url = self._get_oauth_url('access_token')
        self.oauth = OAuth1Session(self.keys['consumer_key'], client_secret=self.keys['consumer_secret'], resource_owner_key=self.request_token['oauth_token'], resource_owner_secret=self.request_token['oauth_token_secret'], verifier=verifier)
        resp = self.oauth.fetch_access_token(url)
        self.keys['access_token'] = resp['oauth_token']
        self.keys['access_token_secret'] = resp['oauth_token_secret']
        return self.keys['access_token'], self.keys['access_token_secret']

    def verify_credentials(self):
        r = requests.get(url="https://api.twitter.com/1.1/account/verify_credentials.json", auth=self.apply_auth())
        data = json.loads(r.content)
        print(data.get('screen_name', ''))
        return 'screen_name' in data

    def get_oauth_header(self):
        r = models.PreparedRequest()
        r.prepare(method="POST", url=self.url, params=self.track)
        o = self.apply_auth()
        o(r)
        return r.headers['Authorization']

    def start(self):
        while self.running:
            if self.conn:
                self.conn.close()
                self.buffer = b''

            self.conn = pycurl.Curl()
            self.conn.setopt(pycurl.SSL_VERIFYPEER, 1)
            self.conn.setopt(pycurl.SSL_VERIFYHOST, 2)
            self.conn.setopt(pycurl.CAINFO, certifi.where())
            self.conn.setopt(pycurl.URL, self.url)
            self.conn.setopt(pycurl.POSTFIELDS, urlencode(self.track))
            self.conn.setopt(pycurl.VERBOSE, 1)
            self.conn.setopt(pycurl.HTTPHEADER, ['Host: stream.twitter.com', 'Authorization: %s' % self.get_oauth_header()])
            self.conn.setopt(pycurl.WRITEFUNCTION, self.handle_tweet)

            backoff_network_error = 0.25
            backoff_http_error = 5
            backoff_rate_limit = 60
            try:
                self.conn.perform()
            except Exception as e:
                print(str(e))
                if str(e) == 'KeyboardInterrupt':
                    self.conn.close()
                    return
                # Network error, use linear back off up to 16 seconds
                print('Network error:', self.conn.errstr())
                print('Waiting', backoff_network_error, 'seconds before trying again')
                time.sleep(backoff_network_error)
                backoff_network_error = min(backoff_network_error + 1, 16)
                continue
            # HTTP Error
            sc = self.conn.getinfo(pycurl.HTTP_CODE)
            if sc == 420:
                # Rate limit, use exponential back off starting with 1 minute and double each attempt
                print('Rate limit, waiting',backoff_rate_limit,'seconds')
                time.sleep(backoff_rate_limit)
                backoff_rate_limit *= 2
            else:
                # HTTP error, use exponential back off up to 320 seconds
                print('HTTP error', sc, ',', self.conn.errstr())
                print('Waiting ',backoff_http_error ,' seconds')
                time.sleep(backoff_http_error)
                backoff_http_error = min(backoff_http_error * 2, 320)

    def handle_tweet(self, data):
        self.buffer += data
        if data.endswith(b'\r\n') and self.buffer.strip():
            # complete message received
            message = json.loads(self.buffer)
            self.buffer = b''
            msg = ''
            if message.get('limit'):
                print('Rate limiting caused us to miss', message['limit'].get('track'),'tweets')
            elif message.get('disconnect'):
                raise Exception('Got disconnect:' + str(message['disconnect'].get('reason')))
            elif message.get('warning'):
                print('Got warning:', message['warning'].get('message'))
            else:
                print(message.get('text'))
                try:
                    print(datetime.utcnow() - datetime.strptime(message.get('created_at'), '%a %b %d %H:%M:%S +0000 %Y'))
                except Exception as e:
                    print(e)

s = Stream({'consumer_key': "",
            'consumer_secret': "",
            'access_token': "",
            'access_token_secret': ""})
if not s.verify_credentials():
    print("failed to authentificate")
else:
    s.start()