using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SecurityCore.Authentications
{
    public static class AuthenticationServiceCollections
    {
        public static void AddAuthentication(this IServiceCollection services)
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
                });
        }
    }
}
