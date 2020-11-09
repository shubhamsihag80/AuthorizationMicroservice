using NUnit.Framework;
using Authorization.Controllers;
using Authorization.Models;
using Authorization.Repository;
using System.Collections.Generic;
using Moq;
using IConfiguration = Microsoft.Extensions.Configuration.IConfiguration;
using Microsoft.AspNetCore.Mvc;
using System.Linq;
using System;

namespace AuthorizationTest
{
    public class Tests
    {
        List<Member> loginDetails;
        Mock<IRepository> mockSet;
        Mock<IConfiguration> config;

       [SetUp]
        public void Setup()
        {
            loginDetails= new List<Member>
            {
                new Member{MemberID=1,MemberName="John",MemberPhone=91999999,MemberCity="Kolkata",MemberAddress1="WB",MemberAddress2="Kol",Username="hell",Password="hell"},

            };
            mockSet = new Mock<IRepository>();
            config = new Mock<IConfiguration>();


        }


        #region Repository testing
        [Test]
        public void GenerateJSONWebToken_ValidMember_ReturnsToken()
        {
            //Arrange
            TokenRepository repo = new TokenRepository();
            config.Setup(p => p["Jwt:Key"]).Returns("ThisIsMySecretKey");
            config.Setup(p => p["Jwr:Issuer"]).Returns("https://localhost:44392");
            mockSet.Setup(m => m.GenerateJSONWebToken(config.Object, loginDetails[0]));
            //Act
            var data = repo.GenerateJSONWebToken(config.Object, loginDetails[0]);
            //Assert
            Assert.IsNotNull(data);
            Assert.AreEqual("string".GetType(), data.GetType());
        }

        [Test]
        public void GenerateJSONWebToken_InvalidMember_ThrowsException()
        {
            //Arrange
            TokenRepository repo = new TokenRepository();
            config.Setup(p => p["Jwt:Key"]).Returns("ThisIsMySecretKey");
            config.Setup(p => p["Jwr:Issuer"]).Returns("https://localhost:44392");
            mockSet.Setup(m => m.GenerateJSONWebToken(config.Object, loginDetails[0]));

            var exceptionMessage=Assert.Throws<NullReferenceException>(()=> repo.GenerateJSONWebToken(config.Object, null));

            Assert.AreEqual("Object reference not set to an instance of an object.",exceptionMessage.Message);
            
            
        }

        #endregion


        #region Controller testing

        [Test]
        public void Controller_Login_ValidCredential_ReturnsOk()
        {
            config.Setup(p => p["Jwt:Key"]).Returns("ThisIsMySecretKey");
            config.Setup(p => p["Jwr:Issuer"]).Returns("https://localhost:44392");
            mockSet.Setup(m => m.GenerateJSONWebToken(config.Object, loginDetails[0]));

            AuthController auth = new AuthController(config.Object,mockSet.Object);
            var data = auth.Login(new LoginModel { Username = "john@123", Password = "Training@123" });
            var dataStatusCode = data as OkObjectResult;
            Assert.IsNotNull(data);
            Assert.AreEqual(200, dataStatusCode.StatusCode);
        }

        [Test]
        public void Controller_Login_InvalidCredential_ReturnsUnauthorized()
        {
            config.Setup(p => p["Jwt:Key"]).Returns("ThisIsMySecretKey");
            config.Setup(p => p["Jwr:Issuer"]).Returns("https://localhost:44392");
            mockSet.Setup(m => m.GenerateJSONWebToken(config.Object, loginDetails[0]));

            AuthController auth = new AuthController(config.Object, mockSet.Object);
            var data = auth.Login(new LoginModel { Username = "abcdef", Password = "defgh" });
            var dataStatusCode = data as UnauthorizedObjectResult;
            Assert.AreEqual("Invalid Credentials", dataStatusCode.Value);
            Assert.AreEqual(401,dataStatusCode.StatusCode);
            
        }

        #endregion
    }
}