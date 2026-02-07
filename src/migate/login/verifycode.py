import requests
import json
from migate.config import (
    HEADERS,
    VERIFY_EM,
    VERIFY_PH,
    console
)

def verify_code_ticket(addressType, cookies):

    url = VERIFY_EM if addressType == "EM" else VERIFY_PH
    
    console.print(f"[white]Check your {('Email' if addressType == 'EM' else 'Phone')} for the code.[/]")
    ticket = console.input("[orange]Enter code: [/]").strip()
    
    response = requests.post(url, data={"ticket": ticket, "trust": "true", '_json': "true"}, headers=HEADERS, cookies=cookies)
    response_text = json.loads(response.text[11:])

    if response_text.get("code") == 0:
        return response_text.get('location')
    elif response_text.get("code") == 70014:
        console.print("Invalid code provided.", style="red")
        return verify_code_ticket(addressType, cookies)
    else:
        return {"error": response_text}
