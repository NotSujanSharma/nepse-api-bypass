from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
import time
import json
import datetime
from requests.packages import urllib3
from urllib.parse import parse_qs
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def aaa():
  print("aaa")


class TokenParser():

  def __init__(self):
    ###############################################MAGIC ARRAY###############################################
    self.data_segment_data_0 = [
      0x09,
      0x00,
      0x00,
      0x00,
      0x08,
      0x00,
      0x00,
      0x00,
      0x04,
      0x00,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x03,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x05,
      0x00,
      0x00,
      0x00,
      0x08,
      0x00,
      0x00,
      0x00,
      0x07,
      0x00,
      0x00,
      0x00,
      0x09,
      0x00,
      0x00,
      0x00,
      0x08,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x03,
      0x00,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x04,
      0x00,
      0x00,
      0x00,
      0x03,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x09,
      0x00,
      0x00,
      0x00,
      0x05,
      0x00,
      0x00,
      0x00,
      0x04,
      0x00,
      0x00,
      0x00,
      0x06,
      0x00,
      0x00,
      0x00,
      0x03,
      0x00,
      0x00,
      0x00,
      0x07,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x06,
      0x00,
      0x00,
      0x00,
      0x09,
      0x00,
      0x00,
      0x00,
      0x08,
      0x00,
      0x00,
      0x00,
      0x04,
      0x00,
      0x00,
      0x00,
      0x01,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x03,
      0x00,
      0x00,
      0x00,
      0x03,
      0x00,
      0x00,
      0x00,
      0x04,
      0x00,
      0x00,
      0x00,
      0x04,
    ]

  def rdx(self, w2c_p0, w2c_p1, w2c_p2, w2c_p3, w2c_p4):

    w2c_i0 = w2c_p1
    w2c_i1 = 100
    w2c_i0 = w2c_i0 // w2c_i1
    w2c_i1 = 10
    w2c_i0 = w2c_i0 % w2c_i1
    w2c_i1 = w2c_p1
    w2c_i2 = 10
    w2c_i1 = w2c_i1 // w2c_i2
    w2c_p0 = w2c_i1
    w2c_i2 = 10
    w2c_i1 = w2c_i1 % w2c_i2
    w2c_i0 += w2c_i1
    w2c_p2 = w2c_i0
    w2c_i1 = w2c_p2
    w2c_i2 = w2c_p1
    w2c_i3 = w2c_p0
    w2c_i4 = 10
    w2c_i3 *= w2c_i4
    w2c_i2 -= w2c_i3
    w2c_i1 += w2c_i2
    w2c_i2 = 2
    w2c_i1 <<= (w2c_i2 & 31)

    w2c_i1 = self.data_segment_data_0[w2c_i1]
    w2c_i0 += w2c_i1
    w2c_i1 = 22
    w2c_i0 += w2c_i1
    return w2c_i0

  def cdx(self, w2c_p0, w2c_p1, w2c_p2, w2c_p3, w2c_p4):
    w2c_i0 = w2c_p1
    w2c_i1 = 10
    w2c_i0 = w2c_i0 // w2c_i1
    w2c_p0 = w2c_i0
    w2c_i1 = 10
    w2c_i0 = w2c_i0 % w2c_i1
    w2c_i1 = w2c_p1
    w2c_i2 = w2c_p0
    w2c_i3 = 10
    w2c_i2 *= w2c_i3
    w2c_i1 -= w2c_i2
    w2c_i0 += w2c_i1
    w2c_i1 = w2c_p1
    w2c_i2 = 100
    w2c_i1 = w2c_i1 // w2c_i2
    w2c_i2 = 10
    w2c_i1 = w2c_i1 % w2c_i2
    w2c_i0 += w2c_i1
    w2c_i1 = 2
    w2c_i0 <<= (w2c_i1 & 31)

    w2c_i0 = self.data_segment_data_0[w2c_i0]
    w2c_i1 = 22
    w2c_i0 += w2c_i1

    return w2c_i0

  def parse_token_response(self, token_response):
    n = self.cdx(token_response['salt1'], token_response['salt2'],
                 token_response['salt3'], token_response['salt4'],
                 token_response['salt5'])
    l = self.rdx(token_response['salt1'], token_response['salt2'],
                 token_response['salt4'], token_response['salt3'],
                 token_response['salt5'])

    i = self.cdx(token_response['salt2'], token_response['salt1'],
                 token_response['salt3'], token_response['salt5'],
                 token_response['salt4'])
    r = self.rdx(token_response['salt2'], token_response['salt1'],
                 token_response['salt3'], token_response['salt4'],
                 token_response['salt5'])

    access_token = token_response['accessToken']
    refresh_token = token_response['refreshToken']

    parsed_access_token = access_token[0:n] + access_token[
      n + 1:l] + access_token[l + 1:]
    parsed_refresh_token = refresh_token[0:i] + refresh_token[
      i + 1:r] + refresh_token[r + 1:]

    #returns both access_token and refresh_token
    #access_token can be used for every new api requests
    return (parsed_access_token, parsed_refresh_token)


class Nepse:

  def __init__(self):
    self.token_parser = TokenParser()

    self.token_url = "https://nepalstock.com/api/authenticate/prove"

    self.headers = {
      'Host': 'nepalstock.com',
      'User-Agent':
      'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
      'Accept': 'application/json, text/plain, */*',
      'Accept-Language': 'en-US,en;q=0.5',
      'Accept-Encoding': 'gzip, deflate, br',
      'Connection': 'keep-alive',
      'Content-Type': 'application/json',
      'Referer': 'https://nepalstock.com/',
      'Pragma': 'no-cache',
      'Cache-Control': 'no-cache',
      'TE': 'Trailers',
    }

  ###############################################PRIVATE METHODS###############################################

  def requestAPI(self, url, access_token=None, post_body=None):
    if access_token is not None:
      headers = {'Authorization': f'Salter {access_token}', **self.headers}
      # print(headers)
    else:
      headers = self.headers

    r = requests.get(url, headers=headers, verify=False)
    # print(r.status_code)
    try:
      return (r.json())
    except:
      try:
        return (r.text)
      except:
        return ({"error": "invalid"}, 403)

  def getValidToken(self):
    token_response = self.requestAPI(url=self.token_url)

    for salt_index in range(1, 6):
      token_response[f'salt{salt_index}'] = int(
        token_response[f'salt{salt_index}'])

    #returns access_token only, refresh token is not used right now
    return self.token_parser.parse_token_response(token_response)[0]

  ###############################################PUBLIC METHODS###############################################

  def get(self, url):
    access_token = self.getValidToken()
    return self.requestAPI(url=url, access_token=access_token)

###################################THIS_IS_JUST_AN_EXAMPLE_OF_USAGE###########################################
nepse = Nepse()
url = 'https://nepalstock.com/api/nots/security/8036'
res = nepse.get(url)
print(res)
