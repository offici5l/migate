import requests
import json
import time
import platform
import subprocess
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from migate.login.sendcode import send_verification_code

from migate.login.verifycode import verify_code_ticket

from miutility.config import (
    HEADERS,
    LIST_URL,
    SERVICELOGINAUTH2_URL
)


def handle_verify(context, auth_data, cookies):
    print(f'\n2FA verification required !\n')

    params = {
        'sid': auth_data["sid"],
        'supportedMask': "0",
        'context': context
    }

    response = requests.get(LIST_URL, params=params, headers=HEADERS, cookies=cookies)

    cookies.update(response.cookies.get_dict())

    result_json = json.loads(response.text[11:])
    options = result_json.get('options', [])

    if 8 in options and 4 in options:
        choice = input(f"\nChoose verification method:\n1 = phone\n2 = email\nEnter 1 or 2: ").strip()
        if choice not in ["1", "2"]:
            exit("\nInvalid choice!")
        addressType = "PH" if choice == "1" else "EM"
    elif 4 in options:
        addressType = "PH"
    elif 8 in options:
        addressType = "EM"
    else:
        exit(result_json)

    send_verification_code(addressType, cookies)

    url = verify_code_ticket(addressType, cookies)

    response = requests.get(url, headers=HEADERS, allow_redirects=False, cookies=cookies)

    url = response.headers.get("Location")

    response = requests.get(url, headers=HEADERS, allow_redirects=False, cookies=cookies)

    cookies.update(response.cookies.get_dict())

    response = requests.post(SERVICELOGINAUTH2_URL, headers=HEADERS, data=auth_data, cookies=cookies)

    response_text = json.loads(response.text[11:])

    return response