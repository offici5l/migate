import requests
import json
from migate.config import (
    HEADERS,
    SEND_EM_TICKET,
    SEND_PH_TICKET,
    USERQUOTA_URL,
    console
)

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
    info_style = "green" if int(info) > 0 else "red"
    console.print(f"[white]Attempts remaining: [/][{info_style}]{info}[/]")
    
    if info == "0":
        return {"error": f"Sent too many codes to {label}. Try again tomorrow."}

    response = requests.post(send_url, headers=HEADERS, cookies=cookies)
    response_text = json.loads(response.text[11:])

    if response_text.get("code") == 87001:
        console.print("\nCAPTCHA verification required for sending code!\n", style="orange")     
        payload = {'icode': "", '_json': "true"}
        response = handle_captcha(send_url, response, cookies, payload, "icode")
        
        if isinstance(response, dict) and "error" in response:
            return response
            
        response_text = json.loads(response.text[11:])

    if response_text.get("code") == 0:
        console.print(f"\nCode sent to {label} successfully.\n", style="green")
        return {"success": True}
    else:
        code = response_text.get("code")
        error_msg = response_text.get("tips", response_text) if code == 70022 else response_text
        return {"error": error_msg}
