import requests
import json
import base64

chave_path = "chave.pem"

with open(chave_path, "rb") as cert_file:
    chave_base64 = base64.b64encode(cert_file.read()).decode("utf-8")

url = "http://localhost:5184/login"

payload = {
    "username": "nomeusuario",
    "email": "email@dominio.com",
    "senha": "senha123",
    "chave": chave_base64,
}

data = json.dumps(payload)

headers = {"Content-Type": "application/json"}

response = requests.post(url, data=data, headers=headers)

if response.status_code == 200:
    json_response = response.json()
    token = json_response.get("token")
    print(f"Login bem sucedido! \n\nToken: {token}")
else:
    error_message = response.content.decode("utf-8")
    print("Resposta completa:\n", error_message)

    first_line = error_message.split("\n")[0]
    print("Erro simplificado:\n", first_line)