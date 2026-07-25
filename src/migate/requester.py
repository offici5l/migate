import requests, json
from migate.config import loader

def parse_res(response):
    return json.loads(response.text[11:])

session = requests.Session()
session.headers.update({
    "User-Agent":      "offici5l/migate",
    "Content-Type":    "application/x-www-form-urlencoded",
    "Accept":          "application/json;charset=UTF-8",
    "Accept-Language": "en-US,en;q=0.9"
})


def get(url, **kwargs):
    return _request("GET", url, **kwargs)


def post(url, **kwargs):
    return _request("POST", url, **kwargs)


def _request(method, url, timeout=30, **kwargs):
    try:
        loader.start()
        response = session.request(method, url, timeout=timeout, **kwargs)
        response.raise_for_status()
        return response
    except requests.exceptions.Timeout:
        raise ConnectionError("Request timed out")
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 403:
            raise ConnectionError("Access denied")
        raise ConnectionError(f"HTTP error: {e.response.status_code}")
    except Exception as e:
        error = str(e)
        if "Failed to resolve" in error:
            raise ConnectionError("No internet connection")
        raise ConnectionError(f"Request failed: {e}")
    finally:
        loader.stop()