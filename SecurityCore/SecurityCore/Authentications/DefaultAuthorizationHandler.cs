using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SecurityCore.Authentications
{
    public class DefaultAuthorizationHandler : AuthorizationHandler<AuthorizationRequirement>
    {
        /// <summary>
        /// 验证方案
        /// </summary>
        public IAuthenticationSchemeProvider Schemes { get; set; }

        /// <summary>
        /// 构造函数注入
        /// </summary>
        /// <param name="schemes"></param>
        public DefaultAuthorizationHandler(IAuthenticationSchemeProvider schemes)
        {
            Schemes = schemes;
        }
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AuthorizationRequirement requirement)
        {
            var resource = context.Resource as AuthorizationFilterContext;
            var descriptor = resource?.ActionDescriptor as ControllerActionDescriptor;

            //.net core 3.x
            if (context.Resource is Endpoint endpoint)
            {
                var controllActionDesription = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>();
                descriptor = controllActionDesription;
            }
            var identity = context.User.Identity;
            var defaultAuthenticate = await Schemes.GetDefaultAuthenticateSchemeAsync();
            if (defaultAuthenticate != null)
            {
                if (identity.IsAuthenticated)
                {
                    context.Succeed(requirement);
                    return;
                }
            }

            context.Fail();
            return;
        }
    }
}
