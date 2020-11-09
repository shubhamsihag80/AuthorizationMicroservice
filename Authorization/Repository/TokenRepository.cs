using Authorization.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Authorization.Repository
{
    public class TokenRepository : IRepository
    {

        /// <summary>
        /// method will generate token
        /// </summary>
        /// <param name="_cofig,memberDetail"></param>
        /// <returns>token</returns>
        public string GenerateJSONWebToken(IConfiguration _config,Member memberDetail)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

                List<Claim> claims = new List<Claim>() {
                    new Claim(JwtRegisteredClaimNames.Sub, memberDetail.Username),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };
                var token = new JwtSecurityToken(
                  _config["Jwt:Issuer"],
                  _config["Jwt:Issuer"],
                  claims,
                  expires: DateTime.Now.AddMinutes(120),
                  signingCredentials: credentials);
                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch(Exception e)
            {
                throw e;
            }
           
        }

    }

    
}
