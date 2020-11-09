using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Authorization.Models;
using Authorization.Repository;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Authorization.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly IConfiguration _config;
        private readonly IRepository _repository;
        static readonly log4net.ILog _log4net = log4net.LogManager.GetLogger(typeof(AuthController));
        public AuthController(IConfiguration config,IRepository repository)
        {
            _config = config;
            _repository = repository;
        }

        /// <summary>
        /// 1.Checking if username and password is valid
        /// 2.Generates jwt token
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        //https://localhost:44392/api/Auth/Login
        [HttpPost]
        [Route("Login")]
        public IActionResult Login([FromBody]LoginModel model)
        {

            try
            {
                _log4net.Info(nameof(Login) + " method invoked, Username : "+model.Username);
                Member memberDetail=CheckCredential(model);
                if (memberDetail != null)
                {
                    var tokenString = _repository.GenerateJSONWebToken(_config,memberDetail);
                    return Ok(tokenString);
                }

                return Unauthorized("Invalid Credentials");
            }
            catch(Exception e)
            {
                _log4net.Error("Error Occured from " + nameof(Login) + "Error Message : " + e.Message);
                return BadRequest(e.Message);
            }



        }


        /// <summary>
        /// method will fetch credential from member service
        /// </summary>
        /// <param name="model"></param>
        /// <returns>Member</returns>
        private Member CheckCredential(LoginModel model)
        {
            try
            {
                _log4net.Info(nameof(CheckCredential) + " method invoked.");
                Member memberDetail;
                var jsonData = JsonConvert.SerializeObject(model);
                var encodedData = new StringContent(jsonData, Encoding.UTF8, "application/json");
                using (var client = new HttpClient())
                {
                    var response = client.PostAsync("http://52.146.70.154/api/Members/", encodedData);
                    var responseData = response.Result.Content.ReadAsStringAsync();
                    memberDetail = JsonConvert.DeserializeObject<Member>(responseData.Result);
                }

                return memberDetail;
            }
            catch(Exception e)
            {
                _log4net.Error("Error Occured from " + nameof(CheckCredential) + "Error Message : " + e.Message);
                
                throw e;
            }
           

        }

    }
}

