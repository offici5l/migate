import requests
import hashlib
import json
from urllib.parse import urlparse, parse_qs
import uuid
from pathlib import Path
import pickle
from migate.config import (
    HEADERS,
    SERVICELOGINAUTH2_URL,
    SERVICELOGIN_URL,
    console
)

def get_passtoken(auth_data):
    sid = auth_data['sid']

    cookies_file = Path.home() / f".{sid}" / "cookies.pkl"
    if cookies_file.exists():
        passToken = pickle.load(open(cookies_file, "rb"))
        
        choice = console.input(
            f"[green]Already logged in[/]\n"
            f"[white]Account ID: [/][orange]{passToken['userId']}[/]\n\n" 
            f"[white]Press 'Enter' to continue[/]\n"
            f"[white](To log out, type [red]2[/] and press Enter.): "
        ).strip().lower()
        
        if choice == "2":
            cookies_file.unlink()
            console.print("Logged out.", style="red")
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
        user = console.input("[white]Account ID / Email / Phone (+): [/]").strip()
        pwd_input = console.input("[white]Password: [/]").strip()
        pwd = hashlib.md5(pwd_input.encode()).hexdigest().upper()
        
        auth_data["user"] = user
        auth_data["hash"] = pwd
        deviceId = "wb_" + str(uuid.UUID(bytes=hashlib.md5((user + pwd + json.dumps(auth_data, sort_keys=True)).encode()).digest()))
        cookies.update({'deviceId': deviceId})
        
        response = requests.post(SERVICELOGINAUTH2_URL, headers=HEADERS, data=auth_data, cookies=cookies)
        response_text = json.loads(response.text[11:])
        
        if response_text.get("code") == 70016:
            console.print("\nInvalid password or username! Please try again.\n", style="red")
            continue
        break

    if response_text.get("code") == 87001:
        console.print("\nCAPTCHA verification required!\n", style="orange")
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

    console.print("\nLogin successful\n", style="green")
    return passToken
