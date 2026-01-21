import requests
import hashlib
import json
from urllib.parse import urlparse, parse_qs
import uuid
from pathlib import Path
import pickle
from colorama import init, Fore, Style

from migate.login.captcha import handle_captcha
from migate.login.verify import handle_verify

from miutility.config import (
    HEADERS,
    SERVICELOGINAUTH2_URL,
    SERVICELOGIN_URL
)

init(autoreset=True)

def get_passtoken(auth_data):
    sid = auth_data['sid']

    cookies_file = Path.home() / f".{sid}" / "cookies.pkl"
    if cookies_file.exists():
        passToken = pickle.load(open(cookies_file, "rb"))
        
        choice = input(
            f"{Fore.GREEN}Already logged in\n"
            f"{Fore.WHITE}Account ID: {Fore.YELLOW}{passToken['userId']}\n\n" 
            f"{Fore.WHITE}Press 'Enter' to continue\n"
            f"(To log out, type {Fore.RED}2{Fore.WHITE} and press Enter.): "
        ).strip().lower()
        
        if choice == "2":
            cookies_file.unlink()
            print(f"{Fore.RED}Logged out.{Style.RESET_ALL}")
        else:
            return passToken

    auth_data["_json"] = True

    try:
        response = requests.get(SERVICELOGIN_URL, params=auth_data)
        response_text = json.loads(response.text[11:])
    except Exception as e:
        return {"error": f"Connection error: {str(e)}"}

    auth_data["serviceParam"] = response_text["serviceParam"]
    auth_data["qs"] = response_text["qs"]
    auth_data["callback"] = response_text["callback"]
    auth_data["_sign"] = response_text["_sign"]

    cookies = {}

    while True:
        user = input(f"{Fore.WHITE}Account ID / Email / Phone (+): {Style.RESET_ALL}").strip()
        pwd_input = input(f"{Fore.WHITE}Password: {Style.RESET_ALL}").strip()
        pwd = hashlib.md5(pwd_input.encode()).hexdigest().upper()
        
        auth_data["user"] = user
        auth_data["hash"] = pwd
        deviceId = "wb_" + str(uuid.UUID(bytes=hashlib.md5((user + pwd + json.dumps(auth_data, sort_keys=True)).encode()).digest()))
        cookies.update({'deviceId': deviceId})
        
        response = requests.post(SERVICELOGINAUTH2_URL, headers=HEADERS, data=auth_data, cookies=cookies)
        response_text = json.loads(response.text[11:])
        
        if response_text.get("code") == 70016:
            print(f"\n{Fore.RED}Invalid password or username! Please try again.\n")
            continue
        break

    if response_text.get("code") == 87001:
        print(f'\n{Fore.YELLOW}CAPTCHA verification required!{Style.RESET_ALL}\n')
        cookies = response.cookies.get_dict()
        response = handle_captcha(SERVICELOGINAUTH2_URL, response, cookies, auth_data, "captCode")
        
        if isinstance(response, dict) and "error" in response:
             return response
             
        response_text = json.loads(response.text[11:])

    if "notificationUrl" in response_text:
        notification_url = response_text["notificationUrl"]
        if any(x in notification_url for x in ["callback", "SetEmail", "BindAppealOrSafePhone"]):
            return {"error": f"Action required at: {notification_url}"}

        context = parse_qs(urlparse(notification_url).query)["context"][0]
        
        verify_result = handle_verify(context, auth_data, cookies)
        
        if isinstance(verify_result, dict) and "error" in verify_result:
            return verify_result
        
        response = verify_result
        response_text = json.loads(response.text[11:])

    cookies = response.cookies.get_dict()

    required = {"deviceId", "passToken", "userId"}
    missing = required - cookies.keys()
    if missing:
        return {"error": f"Missing keys: {', '.join(missing)}"}

    passToken = {k: cookies[k] for k in required}

    cookies_file.parent.mkdir(parents=True, exist_ok=True)
    pickle.dump(passToken, open(cookies_file, "wb"))

    print(f"\n{Fore.GREEN}Login successful\n")
    return passToken
