import requests, json, urllib.parse, os, base64, hashlib

from urllib.parse import parse_qs, urlparse, quote

from migate.config import (
    HEADERS,
    SERVICELOGIN_URL
)

def get_service(cookies, sid):
    response = requests.get(SERVICELOGIN_URL, params={'_json': "true", 'sid': sid}, cookies=cookies, headers=HEADERS)

    response_text = json.loads(response.text[11:])

    nonce = response_text.get('nonce')
    ssecurity = response_text.get('ssecurity')
    location = response_text.get('location')
    cUserId = response_text.get('cUserId')
    psecurity = response_text.get('psecurity')

    sign_text = f"nonce={nonce}&{ssecurity}"
    sha1_digest = hashlib.sha1(sign_text.encode()).digest()
    base64_sign = base64.b64encode(sha1_digest)
    client_sign = quote(base64_sign)

    url = location + f"&clientSign={client_sign}"
    
    response = requests.get(url, headers=HEADERS, cookies=cookies)

    cookies = response.cookies.get_dict()

    servicedata = {
        'nonce': nonce,
        'ssecurity': ssecurity,
        'cUserId': cUserId,
        'psecurity': psecurity,
    }

    service = {'servicedata': servicedata}

    service['cookies'] = cookies

    return service