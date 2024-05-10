# Processo para testar os código:
O processo de validação usa as seguintes coisas:

Chave privada: chave.pem
Certificado público: certificado.pem

Vai precisar gerar a chave e o certificado

Eu usei o OpenSsl pra gerar, ele ja vem por padrão com o git, só precisa adicionar nas variáveis de ambiente em path da máquina.

Vou deixar um código pra rodar no cmd que ja faz isso, e dps outro código pra gerar os arquivos que vai precisar pra testar:

> openssl req -x509 -newkey rsa:4096 -keyout chave.pem -out certificado.pem -sha256 -days 365 -nodes -subj "/CN=DemoApi"

> setx /M PATH "$env:PATH;C:\Program Files\Git\usr\bin"