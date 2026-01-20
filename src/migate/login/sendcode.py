import requests
import json
import time
from pathlib import Path

from migate.login.captcha import handle_captcha

from migate.config import (
    HEADERS,
    BASE_URL,
    SEND_EM_TICKET,
    SEND_PH_TICKET,
    USERQUOTA_URL
)


def send_verification_code(addressType, cookies):

    if addressType == "EM":
        send_url = SEND_EM_TICKET
    else:
        send_url = SEND_PH_TICKET

    payload = {'addressType': addressType, 'contentType': "160040", '_json': "true"}
    response = requests.post(USERQUOTA_URL, data=payload, headers=HEADERS, cookies=cookies)

    response_text = json.loads(response.text[11:])

    info = response_text.get('info')
    print(f"Attempts remaining: {info}")
    if info == "0":
        exit(f"Sent too many codes. (to {addressType} )Try again tomorrow")

    response = requests.post(send_url, headers=HEADERS, cookies=cookies)
    response_text = json.loads(response.text[11:])

    if response_text.get("code") == 87001:
        print(f'\nCAPTCHA verification required !\n')     
        payload = {'icode': "", '_json': "true"}
        response = handle_captcha(send_url, response, cookies, payload, "icode")
        response_text = json.loads(response.text[11:])

    if response_text.get("code") == 0:
        print(f"\nCode sent to {addressType}")
    else:
        code = response_text.get("code")
        error = response_text.get("tips", response_text) if code == 70022 else response_text
        exit(error)
