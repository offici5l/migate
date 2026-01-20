import requests
import json

from migate.config import (
    HEADERS,
    VERIFY_EM,
    VERIFY_PH
)

def verify_code_ticket(addressType, cookies):

    url = VERIFY_EM if addressType == "EM" else VERIFY_PH
    
    ticket = input(f"Enter code: ").strip()
    response = requests.post(url, data={"ticket": ticket, "trust": "true", '_json': "true"}, headers=HEADERS, cookies=cookies)

    response_text = json.loads(response.text[11:])

    if response_text.get("code") == 0:
        url = response_text.get('location')
        return url
    elif response_text.get("code") == 70014:
        #tips = response_text.get("tips")
        print("Invalid code")
        return verify_code_ticket(addressType, cookies)
    else:
        exit(response_text)


