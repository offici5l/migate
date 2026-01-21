import requests
import json
from colorama import init, Fore, Style

from migate.login.captcha import handle_captcha
from migate.config import (
    HEADERS,
    SEND_EM_TICKET,
    SEND_PH_TICKET,
    USERQUOTA_URL
)

init(autoreset=True)

def send_verification_code(addressType, cookies):

    if addressType == "EM":
        send_url = SEND_EM_TICKET
        label = "Email"
    else:
        send_url = SEND_PH_TICKET
        label = "Phone"

    payload = {'addressType': addressType, 'contentType': "160040", '_json': "true"}
    response = requests.post(USERQUOTA_URL, data=payload, headers=HEADERS, cookies=cookies)
    response_text = json.loads(response.text[11:])

    info = response_text.get('info')
    info_color = Fore.GREEN if int(info) > 0 else Fore.RED
    print(f"{Fore.WHITE}Attempts remaining: {info_color}{info}{Style.RESET_ALL}")
    
    if info == "0":
        return {"error": f"Sent too many codes to {label}. Try again tomorrow."}

    response = requests.post(send_url, headers=HEADERS, cookies=cookies)
    response_text = json.loads(response.text[11:])

    if response_text.get("code") == 87001:
        print(f'\n{Fore.YELLOW}CAPTCHA verification required for sending code!{Style.RESET_ALL}\n')     
        payload = {'icode': "", '_json': "true"}
        response = handle_captcha(send_url, response, cookies, payload, "icode")
        
        if isinstance(response, dict) and "error" in response:
            return response
            
        response_text = json.loads(response.text[11:])

    if response_text.get("code") == 0:
        print(f"\n{Fore.GREEN}Code sent to {label} successfully.{Style.RESET_ALL}")
        return {"success": True}
    else:
        code = response_text.get("code")
        error_msg = response_text.get("tips", response_text) if code == 70022 else response_text
        return {"error": error_msg}
