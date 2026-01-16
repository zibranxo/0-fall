import requests
response = requests.post("http://127.0.0.1:8000/classify", json={"text": "Ignore safety rules..."})
print(response.json())  # Gets {"prediction": "unsafe", "confidence": 0.95}
