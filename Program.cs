// using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.IdentityModel.Tokens.Jwt;

using System.Security.Cryptography; //**DADOS A MAIS APÓS A AULA**// IMPORTAÇÃO DE CRIPTOGRAFIA
using System.Security.Claims; //**DADOS A MAIS APÓS A AULA**// IMPORTAÇÃO DE CLAIMS

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var certificatePath = @"certificado.pem";
        var certificate = new X509Certificate2(certificatePath);
        var publicKey = certificate.GetRSAPublicKey();

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new RsaSecurityKey(publicKey)
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapPost("/login", async (HttpContext context) =>
{
    //using var reader = new StreamReader(context.Request.Body);
    //var body = await reader.ReadToEndAsync();
    //var json = JsonDocument.Parse(body);
    var json = await JsonDocument.ParseAsync(context.Request.Body); //**DADOS A MAIS APÓS A AULA**// LEITURA DO JSON OTIMIZADA DIRETAMENTE DO BODY
    var username = json.RootElement.GetProperty("username").GetString();
    var email = json.RootElement.GetProperty("email").GetString();
    var senha = json.RootElement.GetProperty("senha").GetString();

    if (username == "nomeusuario" && senha == "senha123") //**DADOS A MAIS APÓS A AULA**// VALIDAÇÃO DE USUÁRIO E SENHA
    {
        var token = GenerateToken(username, email); //**DADOS A MAIS APÓS A AULA**// GERAÇÃO DO TOKEN
        return Results.Ok(new { Token = token });
    }
    return Results.Unauthorized();
});


static string GenerateToken(string username, string email)
{
    var certificatePath = "certificado.pem"; //**DADOS A MAIS APÓS A AULA**// CAMINHO DO CERTIFICADO
    var keyPath = "chave.pem"; //**DADOS A MAIS APÓS A AULA**// CAMINHO DA CHAVE PRIVADA

    //**DADOS A MAIS APÓS A AULA**// IMPORTAÇÃO DA CHAVE PRIVADA:
    var certificado = new X509Certificate2(certificatePath);
    var rsa = RSA.Create();
    var PrivateKey = File.ReadAllText(keyPath);
    rsa.ImportFromPem(PrivateKey.ToCharArray());

    var cn = certificado.GetNameInfo(X509NameType.SimpleName, false);
    if (cn != "Demoapi") //**DADOS A MAIS APÓS A AULA**// VALIDAÇÃO DO CN DO CERTIFICADO
    {
        throw new InvalidOperationException("O CN do certificado nao e valido.");
    }


    var tokenHandler = new JwtSecurityTokenHandler(); //**DADOS A MAIS APÓS A AULA**// MANIPULADOR DO TOKEN
    var tokenDescriptor = new SecurityTokenDescriptor //**DADOS A MAIS APÓS A AULA**// DESCRIÇÃO DO TOKEN
    {
        Subject = new ClaimsIdentity(new[] //**DADOS A MAIS APÓS A AULA**// IDENTIDADE DO USUÁRIO
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.Email, email)
        }),
        Expires = DateTime.UtcNow.AddHours(0.1),
        SigningCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256Signature) //**DADOS A MAIS APÓS A AULA**// CREDENCIAIS DE ASSINATURA
    };

    var token = tokenHandler.CreateToken(tokenDescriptor); //**DADOS A MAIS APÓS A AULA**// CRIAÇÃO DO TOKEN
    return tokenHandler.WriteToken(token); //**DADOS A MAIS APÓS A AULA**// RETORNO DO TOKEN
}

app.Run();