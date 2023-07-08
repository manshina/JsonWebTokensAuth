using firebirdDbFirstAndJWT.Models;
using firebirdDbFirstAndJWT.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;
using System.Text.Json.Serialization;
using testTablesWithRoles.Data;
using testTablesWithRoles.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers().AddJsonOptions(x =>
                x.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles);

builder.Services.Configure<AuthOptions>(builder.Configuration.GetSection("Auth"));

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ITokenService, TokenServise>();

builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey
    });

    options.OperationFilter<SecurityRequirementsOperationFilter>();
});

var authOptions = builder.Configuration.GetSection("Auth").Get<AuthOptions>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = authOptions.Issuer,
        ValidateAudience = true,
        ValidAudience = authOptions.Audience,
        ValidateLifetime = true,
        IssuerSigningKey = authOptions.GetSymmetricSecurityKey(),
        ValidateIssuerSigningKey = true

    };
}
);

builder.Services.AddDbContext<ProjectContext>(option => 
{
    option.UseSqlServer(builder.Configuration.GetSection("connectionStrings:default").Value);
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
