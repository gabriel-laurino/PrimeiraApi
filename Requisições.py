import requests
import json
import base64

#chave_path = "./chave.pem"

#with open(chave_path, "rb") as cert_file:
    #chave_base64 = base64.b64encode(cert_file.read()).decode("utf-8")

urlToken = "http://localhost:5184/login"

payloadToken = {
    "username": "nomeusuario",
    "email": "email@dominio.com",
    "senha": "1029",
    # "chave": chave_base64,
}

dataToken = json.dumps(payloadToken)

headersToken = {"Content-Type": "application/json"}

response = requests.post(urlToken, data=dataToken, headers=headersToken)

'''
if response.status_code == 200:
    json_response = response.json()
    token = json_response.get("token")
    print(f"Login bem sucedido! \n\nToken: {token}")
else:
    error_message = response.content.decode("utf-8")
    print("Resposta completa:\n", error_message)

    first_line = error_message.split("\n")[0]
    print("Erro simplificado:\n", first_line)
'''
    
if response.status_code == 200:
    token = response.content.decode("utf-8").strip()
    print(f"Login bem sucedido! \n\nToken: {token}")
else:
    error_message = response.content.decode("utf-8")
    print("Resposta completa:\n", error_message)

    first_line = error_message.split("\n")[0]
    print("Erro simplificado:\n", first_line)
    token = ""

#chave_path = "./chave.pem"

#with open(chave_path, "rb") as cert_file:
    #chave_base64 = base64.b64encode(cert_file.read()).decode("utf-8")

url = "http://localhost:5184/rotaSegura"

payload = {
    "token": token,
    # "chave": chave_base64,
}

data = json.dumps(payloadToken)

headers = {"Content-Type": "application/json",
           "Authorization": "Bearer/token"}

response2 = requests.post(url, data=data, headers=headers)

'''
if response.status_code == 200:
    json_response = response.json()
    token = json_response.get("token")
    print(f"Login bem sucedido! \n\nToken: {token}")
else:
    error_message = response.content.decode("utf-8")
    print("Resposta completa:\n", error_message)

    first_line = error_message.split("\n")[0]
    print("Erro simplificado:\n", first_line)
'''
    
if response2.status_code == 200:
    token = response2.content.decode("utf-8").strip()
    print(f"Usuario autorizado")
else:
    error_message = response2.content.decode("utf-8")
    print("Resposta completa:\n", error_message)

    first_line = error_message.split("\n")[0]
    print("Erro simplificado:\n", first_line)