import requests
import json
from urllib.parse import urlparse, parse_qs
from migate.login.sendcode import send_verification_code
from migate.login.verifycode import verify_code_ticket
from migate.config import HEADERS, LIST_URL, SERVICELOGINAUTH2_URL, console

def handle_verify(context, auth_data, cookies):
    console.print("\n=== 2FA Verification Required ===\n", style="orange")

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
        console.print("Choose verification method:", style="white")
        console.print("[orange]1[/][white] = Phone (SMS)[/]")
        console.print("[orange]2[/][white] = Email[/]")
        choice = console.input("[white]Enter 1 or 2: [/]").strip()
        
        if choice not in ["1", "2"]:
            return {"error": "Invalid choice!"}
        addressType = "PH" if choice == "1" else "EM"
    elif 4 in options:
        addressType = "PH"
    elif 8 in options:
        addressType = "EM"
    else:
        return {"error": f"No supported verification options found. (Response: {result_json})"}

    send_result = send_verification_code(addressType, cookies)
    if isinstance(send_result, dict) and "error" in send_result:
        return send_result

    verify_result = verify_code_ticket(addressType, cookies)
    if isinstance(verify_result, dict) and "error" in verify_result:
        return verify_result
    
    url = verify_result

    response = requests.get(url, headers=HEADERS, allow_redirects=False, cookies=cookies)
    url = response.headers.get("Location")
    response = requests.get(url, headers=HEADERS, allow_redirects=False, cookies=cookies)
    cookies.update(response.cookies.get_dict())

    response = requests.post(SERVICELOGINAUTH2_URL, headers=HEADERS, data=auth_data, cookies=cookies)
    
    return response
