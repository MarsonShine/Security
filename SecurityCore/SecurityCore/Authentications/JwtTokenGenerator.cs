using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

namespace SecurityCore.Authentications
{
    public class JwtTokenGenerator
    {
        /// <summary>
        /// 获取基于JWT的Token
        /// </summary>
        /// <returns></returns>
        public static string BuildJwtToken(Claim[] claims, AuthorizationRequirement requirement)
        {
            var now = DateTime.Now;
            // 实例化JwtSecurityToken
            var jwt = new JwtSecurityToken(
                issuer: requirement.Issuer,
                audience: requirement.Audience,
                claims: claims,
                notBefore: now,
                expires: now.Add(requirement.Expiration),
                signingCredentials: requirement.SigningCredentials
            );
            // 生成 Token
            var encodedJwt = new JwtSecurityTokenHandler().WriteToken(jwt);

            //打包返回前台
            return encodedJwt;
        }
    }
}
