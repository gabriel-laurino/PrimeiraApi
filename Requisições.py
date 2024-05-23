import requests
import json

urlToken = "http://localhost:5184/login"

payloadToken = {
    "username": "nomeusuario",
    "email": "email@dominio.com",
    "senha": "1029",
}

dataToken = json.dumps(payloadToken)
headersToken = {"Content-Type": "application/json"}

response = requests.post(urlToken, data=dataToken, headers=headersToken)

if response.status_code == 200:
    json_response = response.json()
    token = json_response.get("token")
    print(f"Login bem sucedido! \n\nToken: {token}")
else:
    error_message = response.content.decode("utf-8")
    print("Resposta completa:\n", error_message)
    first_line = error_message.split("\n")[0]
    print("Erro simplificado:\n", first_line)
    token = ""

if token:
    url = "http://localhost:5184/rotaSegura"
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Gera uma exceção se o status não for 200

        if response.status_code == 200:
            print("\nUsuario autorizado")
        else:
            error_message = response.content.decode("utf-8")
            print("\nResposta completa:\n", error_message)
            first_line = error_message.split("\n")[0]
            print("\nErro simplificado:\n", first_line)
    except requests.exceptions.RequestException as e:
        print(f"\nErro na requisição para a rota segura: {e}")
else:
    print("\nNão foi possível obter o token.")
