#!/usr/bin/env python
import os

# Allow for 2FA secret generation, and 2FA entry via TOTP code or secret.
# Password and TOTP/secret via getpass function to try to stop echo to terminal.

import requests
import json
import getpass
import base64
import hmac
import struct
import time

def awareTOTP(secret):
    # Generate the OTP from the secret.
    secret = base64.b32decode(secret + '=' * ((8 - len(secret)) % 8), casefold=True)
    counter = (int(time.time() / 30))
    # Create the mac for the key and message(counter)
    mac = hmac.digest(secret, struct.pack('>Q', counter), "sha1")
    # Determine the offset and extract 31 bits from this offset
    offset = mac[-1] & 0x0f
    output = struct.unpack('>L', mac[offset:offset + 4])[0] & 0x7fffffff
    # Return the last 6 digits (padded with zeros)
    return '{:=06}'.format(output % 1000000)

def awareGet(session, url):
    resp = session.get(url, timeout=1)
    if (resp.status_code != 200):
        print("GET failed for", url, "returned", resp.status_code)
        resp.raise_for_status()
    return (resp.json())

def awarePost(session, url, data):
    resp = session.post(url, data=json.dumps(data), timeout=1)
    if (resp.status_code != 200):
        print("failed to post to", url, "returned", resp.status_code)
        resp.raise_for_status()
    if len(resp.content) > 0:
        return (resp.json())
    else:
        return ()

def awarePut(session, url, data):
    resp = session.put(url, data=json.dumps(data), timeout=1)
    if (resp.status_code != 200):
        print("failed to put to", url, "returned", resp.status_code)
        resp.raise_for_status()
    return ()

def doLogin(session, host, username, password):
    loginURL = host + "/api/v1/dologin"
    cred = {"username": username, "password": password}
    awarePost(session, loginURL, cred)
    return ()

def getAuthInfo(session, host):
    url = host + "/api/v1/auth"
    resp = awareGet(session, url)
    return (resp)

def postTOTP(session, host, totp, name):
    url = host + "/api/v1/totp"
    data = {"code": totp, "name": name}
    awarePost(session, url, data)
    return ()

def postMyTOTP(session, host):
    url = host + "/api/v1/me/totp"
    data = {}
    resp = awarePost(session, url, data)
    return (resp)

def putMyTOTP(session, host, totp, name, uri):
    url = host + "/api/v1/me/totp"
    data = {"verification_code": totp, "name": name, "uri": uri}
    awarePut(session, url, data)
    return ()

def getUsers(session, host):
    url = host + "/api/v1/users"
    resp = awareGet(session, url)
    return (resp)

def getDevices(session, host):
    url = host + "/api/v1/devices"
    resp = awareGet(session, url)
    return (resp)

def loginMatrix():
    url = "https://matrix.api.viametrics.com/v1/auth/login"
    payload = json.dumps({
        "email": "bengt.hagman@viametrics.com",
        "password": "2lkoPP.1966"
    })
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.request("POST", url, headers=headers, data=payload)

    print(response.text)
    return json.loads(response.text)

def matrixUpload(jwt, matrixID, payload):
    url = "https://matrix.api.viametrics.com/v1/admin/import/counterdata?period=900&mode=SAVE_NEW"

    headers = {
        'Content-Type': 'text/plain',
        'Authorization': 'Bearer ' + jwt
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    print(response.text)

def getCounts(session, host, id):
    from datetime import datetime, timedelta
    yesterday = datetime.now() - timedelta(4)

    type(yesterday)
    #    datetime.datetime
    yr = datetime.strftime(yesterday, '%Y')
    mo = datetime.strftime(yesterday, '%m')
    dy = datetime.strftime(yesterday, '%d')

    url = host + "/api/v1/countingAreas/" + id + "/counts?start=" + yr + "-" + mo + "-" + dy \
          + "T00%3A00%3A00Z&step=900000&time_location=DST"
    resp = awareGet(session, url)
    return (resp)


def doUpload(camID, matrixID, jwt1):
    payload = ""
    counts = getCounts(session, host, camID)

    for count in counts['totals']:
        in1 = count['countPersonIn']
        ut1 = count['countPersonOut']
        s, ms = divmod(count['received'], 1000)
        sTime = '%s' % (time.strftime('%Y-%m-%d %H:%M', time.localtime(s)))
        #    sTime = '%s.%03d' % (time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s)), ms)
        print(in1, ut1, sTime)
        # 2013-10-08 10:00,2,1,900,29381\r\n
        if payload == "":
            payload = str(sTime) + ',' + str(in1) + ',' + str(ut1) + ',900,' + str(matrixID)
        else:
            payload = payload + '\r\n' + str(sTime) + ',' + str(in1) + ',' + str(ut1) + ',900,' + str(matrixID)
            print(payload)
        #  data is formatted and ready to be added to post
        matrixUpload(jwt1, matrixID, payload)

#  Start basic operation
session = requests.Session()

host = "https://via-vika.eu1.aware.avasecurity.com"
username = "bengt.hagman@viametrics.com"
password = "1liteT4Torn"

# Authenticate with server.
doLogin(session,host, username, password)
# Read the MFA info to determine whether 2FA is required.
authInfo = getAuthInfo(session, host)
# If MFA needs to be set up, then do so
print(authInfo)
if (authInfo['mfaResetRequired']):
    from urllib import parse
    setup = postMyTOTP(session, host)
    secret = (dict(parse.parse_qsl(parse.urlsplit(setup['uri']).query)))['secret']
    print("The secret value is", secret, "don't lose it")
    putMyTOTP(session, host, awareTOTP(secret), "", setup['uri'])

elif (authInfo['mfaChallengeRequired']):
    secret = "4BIAQTT7MN36C7LQGLDCWLFMZGSBBUU6"
    if len(secret) != 6:
        print("Generating 2FA")
        postTOTP(session, host, awareTOTP(secret), "")
    else:
        postTOTP(session, host, secret, "")

# Get the list of users and if successful, print it.
# users = getUsers(session, host)
# print("Found", len(users), "users")
# for user in users:
#     print("id:", user['id'], "username:", user['username'])

# Get the list of devices and if successful, print it.
# devices = getDevices(session, host)
# print("Found", len(devices), "devices")
# print(devices)
# for device in devices:
#    print("id:", device['id'], "name:", device['name'])

# start by getting token for Matrix
LoginMatr = loginMatrix()
jwt1 = LoginMatr["jwt"]
print(jwt1)

doUpload("7ec41c84-992b-47a7-bd5f-13b50c2fd783",33234, jwt1)
doUpload("37442187-3843-445b-9430-2c01c19f9b02",32845, jwt1)
doUpload("6e2ec9de-5e24-4b16-9491-d93fd413bec6",32838, jwt1)
doUpload("83ef6382-94f2-40ec-8ad1-e84910cf85d0",32839, jwt1)
doUpload("0b2a3687-a3cb-4d20-9859-cccfadd42b59",32840, jwt1)
doUpload("45adbcbf-31af-4054-86c7-258a9e2bfd90",32841, jwt1)
doUpload("f87bb4fd-0f1f-47fb-8739-e833522e890c",32842, jwt1)
doUpload("5d0088d3-4209-45d5-b737-ed471053f609",32846, jwt1)
doUpload("aacbc145-fd66-4d39-9921-74ee80de046b",32843, jwt1)
