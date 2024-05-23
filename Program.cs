using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

string secretKey = "dfhviocsjserkvknkjsdajvbejnvjfjsdf";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey))
        };
    });

var app = builder.Build();

app.UseHttpsRedirection();

string GenerateToken(string data)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = new SigningCredentials(
            new SymmetricSecurityKey(Encoding.ASCII.GetBytes(secretKey)),
            SecurityAlgorithms.HmacSha256Signature
        )
    };
    var token = tokenHandler.CreateToken(tokenDescriptor);
    return tokenHandler.WriteToken(token);
}

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
        await context.Response.WriteAsync("\nToken não fornecido");
        return;
    }

    var token = context.Request.Headers["Authorization"].ToString().Replace("Bearer ", "");

    var tokenValidator = new TokenValidator(secretKey);
    if (!tokenValidator.ValidarToken(token, out ClaimsPrincipal? principal))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsync("\nToken inválido");
        return;
    }

    await context.Response.WriteAsync("\nAutorizado");
});

app.Run();
