import os
import time
import webbrowser
import requests
import json
import http.server
import socketserver
import threading
from pathlib import Path
import platform

from migate.config import (
    HEADERS,
    BASE_URL
)

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def start_temp_server(directory):
    handler = lambda *args: QuietHandler(*args, directory=directory)
    httpd = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]

    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    return httpd, port

def handle_captcha(send_url, response, cookies, payload, capt_key):
    response_text = json.loads(response.text[11:])
    cap_url = BASE_URL + response_text["captchaUrl"]
    response = requests.get(cap_url, headers=HEADERS)
    cookies.update(response.cookies.get_dict())
    captcha_filename = f"{int(time.time())}_captcha.jpg"
    captcha_dir = Path.home()
    captcha_path = captcha_dir / captcha_filename

    with open(captcha_path, "wb") as f:
        f.write(response.content)

    httpd, port = start_temp_server(str(captcha_dir))
    local_url = f"http://127.0.0.1:{port}/{captcha_filename}"
    
    if platform.system() == "Linux":
        os.system("xdg-open '" + local_url + "'")
    else:
        webbrowser.open(local_url)

    print(f"check browser: {local_url}")
    user_input = input(f"Enter Captcha: ")
    payload[capt_key] = user_input

    httpd.shutdown()
    httpd.server_close()

    response = requests.post(send_url, headers=HEADERS, data=payload, cookies=cookies)
    
    os.remove(captcha_path)

    response_text = json.loads(response.text[11:])

    if response_text.get("code") == 87001:
        print("\nIncorrect captcha code\n")
        return handle_captcha(send_url, response, cookies, payload, capt_key)

    return response
