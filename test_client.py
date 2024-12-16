import requests
import json

def test_url(url_to_test):
    url = "http://127.0.0.1:8000/analyze"
    data = {'url': url_to_test}
    headers = {'Content-type': 'application/json'}
    try:
        response = requests.post(url, data=json.dumps(data), headers=headers)
        response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None

if __name__ == "__main__":
    test_urls = [
        "https://www.google.com",
        "https://www.wellsfarg0.com/",
        "http://google.com",
        "https://www.facebook.com"
    ]
    for test_url in test_urls:
        result = test_url(test_url)
        if result:
            print(json.dumps(result,indent=4))