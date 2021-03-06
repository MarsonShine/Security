﻿using IdentityModel;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityCore.Authentications
{
    public static class AuthenticationServiceCollections
    {
        public static void AddSecurityAuthentication(this IServiceCollection services)
        {
            //services.AddAuthentication(options =>
            //{
            //    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            //    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            //});
            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options => {
                    options.SaveToken = true;
                    options.Events = new JwtBearerEvents()
                    {
                        // 注册验证相关的回调事件
                    };
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        ValidateIssuer = true,
                        ValidateAudience = true,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero,
                        RequireExpirationTime = true,
                        NameClaimType = JwtClaimTypes.Name,
                        RoleClaimType = JwtClaimTypes.Role,
                        //Token颁发机构
                        ValidIssuer = "Issuer",
                        //颁发给谁
                        ValidAudience = "Audience",
                        //这里的key要进行加密
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("密钥")),
                    };
                });
            services.AddSingleton<IAuthorizationHandler, DefaultAuthorizationHandler>();

            // 授权
            services.AddSecurityAuthorization();
        }

        public static void AddSecurityAuthorization(this IServiceCollection services)
        {
            services.AddAuthorization(options =>
            {
                options.AddPolicy("EmployeeOnly", policy => policy.RequireClaim("EmployeeNumber"));
                // 可以指定具体的值
                options.AddPolicy("Founders", policy => policy.RequireClaim("EmployeeNumber", "1", "2", "3", "4"));
                options.AddPolicy("CustomAthorization", policy => policy.Requirements.Add(new AuthorizationRequirement() { 
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(Encoding.UTF8.GetBytes("密钥")),SecurityAlgorithms.HmacSha256)
                    // 各种必要的验证参数
                }));
            });
            
        }
    }
}
