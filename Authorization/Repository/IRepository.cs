using Authorization.Models;
using Microsoft.Extensions.Configuration;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authorization.Repository
{
    public interface IRepository
    {
        
      

       public string GenerateJSONWebToken(IConfiguration _congig,Member memberDetail);
    }
}
