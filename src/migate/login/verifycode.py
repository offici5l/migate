import requests
import json
from colorama import init, Fore, Style

from migate.config import (
    HEADERS,
    VERIFY_EM,
    VERIFY_PH
)

init(autoreset=True)

def verify_code_ticket(addressType, cookies):

    url = VERIFY_EM if addressType == "EM" else VERIFY_PH
    
    print(f"{Fore.WHITE}Check your {('Email' if addressType == 'EM' else 'Phone')} for the code.")
    ticket = input(f"{Fore.YELLOW}Enter code: {Style.RESET_ALL}").strip()
    
    response = requests.post(url, data={"ticket": ticket, "trust": "true", '_json': "true"}, headers=HEADERS, cookies=cookies)
    response_text = json.loads(response.text[11:])

    if response_text.get("code") == 0:
        return response_text.get('location')
    elif response_text.get("code") == 70014:
        print(f"{Fore.RED}Invalid code provided.{Style.RESET_ALL}")
        return verify_code_ticket(addressType, cookies)
    else:
        return {"error": response_text}
