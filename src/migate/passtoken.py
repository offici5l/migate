import requests
import hashlib
import json
from urllib.parse import urlparse, parse_qs
import json
import uuid
from pathlib import Path
import pickle

from migate.login.captcha import handle_captcha
from migate.login.verify import handle_verify

from miutility.config import (
    HEADERS,
    SERVICELOGINAUTH2_URL,
    SERVICELOGIN_URL
)

def get_passtoken(auth_data):

    sid = auth_data['sid']

    cookies_file = Path.home() / f".{sid}" / "cookies.pkl"
    if cookies_file.exists():
        passToken = pickle.load(open(cookies_file, "rb"))
        choice = input(
            f"\nAlready logged in\n"
            f"Account ID: {passToken['userId']}\n\n"
            f"Press 'Enter' to continue\n"
            f"(To log out, type 2 and press Enter.)"
        ).strip().lower()
        if choice == "2":
            cookies_file.unlink()
        else:
            return passToken

    auth_data["_json"] = True

    response = requests.get(SERVICELOGIN_URL, params=auth_data)
    response_text = json.loads(response.text[11:])

    auth_data["serviceParam"] = response_text["serviceParam"]
    auth_data["qs"] = response_text["qs"]
    auth_data["callback"] = response_text["callback"]
    auth_data["_sign"] = response_text["_sign"]

    cookies = {}

    while True:
        user = input("Username: ").strip()
        pwd = hashlib.md5(input("Password: ").strip().encode()).hexdigest().upper()
        auth_data["user"] = user
        auth_data["hash"] = pwd
        deviceId = "wb_" + str(uuid.UUID(bytes=hashlib.md5((user + pwd + json.dumps(auth_data, sort_keys=True)).encode()).digest()))
        cookies.update({'deviceId': deviceId})
        response = requests.post(SERVICELOGINAUTH2_URL, headers=HEADERS, data=auth_data, cookies=cookies)
        response_text = json.loads(response.text[11:])
        if response_text.get("code") == 70016:
            print(f"\nInvalid password! or username Please try again.\n")
            continue
        break

    if response_text.get("code") == 87001:
        print(f'\nCAPTCHA verification required !\n')
        cookies = response.cookies.get_dict()
        response = handle_captcha(SERVICELOGINAUTH2_URL, response, cookies, auth_data, "captCode")
        response_text = json.loads(response.text[11:])

    if "notificationUrl" in response_text:
        notification_url = response_text["notificationUrl"]
        if any(x in notification_url for x in ["callback", "SetEmail", "BindAppealOrSafePhone"]):
            exit(notification_url)
        context = parse_qs(urlparse(notification_url).query)["context"][0]
        response = handle_verify(context, auth_data, cookies)
        response_text = json.loads(response.text[11:])

    cookies = response.cookies.get_dict()

    required = {"deviceId", "passToken", "userId"}
    missing = required - cookies.keys()
    if missing:
        return {"error": f"Missing keys: {', '.join(missing)}"}

    passToken = {k: cookies[k] for k in required}

    cookies_file.parent.mkdir(parents=True, exist_ok=True)
    pickle.dump(passToken, open(cookies_file, "wb"))

    print("\nLogin successful\n")
    return passToken


