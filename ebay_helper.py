import sys
import os
import requests
import urllib
import base64
import json

from werkzeug.exceptions import InternalServerError, BadRequest

EBAY_VARS = {
    "base_auth_url": "auth.sandbox.ebay.com",
    "base_api_url": "api.sandbox.ebay.com",
    "appid": "OMITTED",
    "certid": "OMITTED",
    "devid": "OMITTED",
    "redirecturi": "OMITTED",
}

app_scopes = [
    "https://api.ebay.com/oauth/api_scope",
    "https://api.ebay.com/oauth/api_scope/commerce.identity.name.readonly",
    "https://api.ebay.com/oauth/api_scope/commerce.identity.readonly",
    "https://api.ebay.com/oauth/api_scope/sell.inventory",
    "https://api.ebay.com/oauth/api_scope/sell.marketing",
    "https://api.ebay.com/oauth/api_scope/sell.account",
    "https://api.ebay.com/oauth/api_scope/sell.fulfillment",
]

def generate_authorization_url():
    global EBAY_VARS
    global app_scopes
    url_encoded_scopes = urllib.parse.quote_plus(' '.join(app_scopes))
    url = "https://" + EBAY_VARS["base_auth_url"] + "/oauth2/authorize?client_id=" + EBAY_VARS["appid"] + "&redirect_uri=" + EBAY_VARS["redirecturi"] + "&response_type=code&scope=" + url_encoded_scopes
    return url

def get_access_token_from_code(code):
    global EBAY_VARS
    payload = {
        "grant_type": "authorization_code",
        "code": str(code),
        "redirect_uri": EBAY_VARS["redirecturi"]
    
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": b"Basic " + base64.b64encode(EBAY_VARS["appid"].encode() + b":" + EBAY_VARS["certid"].encode())
    }

    try:
        r = requests.post("https://" + EBAY_VARS["base_api_url"] + "/identity/v1/oauth2/token", headers=headers, data=payload)
    except Exception:
        return None
    
    if 'access_token' in str(r.content):
        return r.json()
    return None

def get_access_token_from_refresh_token(refresh_token):
    global EBAY_VARS
    global app_scopes
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": str(refresh_token),
        "scope": ' '.join(app_scopes)
    }
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": b"Basic " + base64.b64encode(EBAY_VARS["appid"].encode() + b":" + EBAY_VARS["certid"].encode())
    }

    try:
        r = requests.post("https://" + EBAY_VARS["base_api_url"] + "/identity/v1/oauth2/token", headers=headers, data=payload)
    except Exception:
        return None
    
    if 'access_token' in str(r.content):
        return r.json()
    return None

def get_userinfo_from_access_token(access_token):
    r=requests.get("https://apiz.sandbox.ebay.com/commerce/identity/v1/user/", headers={"Authorization":"Bearer " + str(access_token)})
    return(r.json())