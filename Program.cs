using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes("abc"))
        };
    });

var app = builder.Build();

app.UseHttpsRedirection();

app.MapPost("/login", async (HttpContext context) =>
{
    using var reader = new StreamReader(context.Request.Body);
    var body = await reader.ReadToEndAsync();

    var json = JsonDocument.Parse(body);
    var username = json.RootElement.GetProperty("username").GetString();
    var email = json.RootElement.GetProperty("email").GetString();
    var senha = json.RootElement.GetProperty("senha").GetString();

    var token = "";
    if (senha == "1029")
    {
        token = GenerateToken(email);
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsync(JsonSerializer.Serialize(new { token }));
        return;
    }

    context.Response.StatusCode = 401; // Unauthorized
    await context.Response.WriteAsync("Usuário ou senha inválidos");
});

// Rota Segura

app.MapGet("/rotaSegura", async (HttpContext context) =>
{
    if (!context.Request.Headers.ContainsKey("Authorization"))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Token não fornecido");
        return "Token não fornecido";
    }

    // Obter o token
    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

    // Validar o token
    var tokenValidator = new TokenValidator("dfhviocsjserkvknkjsdajvbejnvjfjsdf");
    if (!tokenValidator.ValidarToken(token, out ClaimsPrincipal? principal))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("Token Invalido");
        return "Token invalido";
    }

    // Se o token é válido: Dar andamento na lógica do endPoint.
    await context.Response.WriteAsync("Autorizado");
    return "Autorizado";
});

string GenerateToken(string data)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var secretKey = Encoding.ASCII.GetBytes("dfhviocsjserkvknkjsdajvbejnvjfjsdf"); // Esta chave será gravada em uma variável de ambiente
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Expires = DateTime.UtcNow.AddHours(1), // O token expira em 1 hora
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(secretKey),
            SecurityAlgorithms.HmacSha256Signature
        )
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token); // Converte o token em string
}

app.Run();
