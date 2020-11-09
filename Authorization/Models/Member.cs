using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Authorization.Models
{
    public class Member
    {
        public int MemberID { get; set; }
        public string MemberName { get; set; }
        public string MemberAddress1 { get; set; }
        public string MemberAddress2 { get; set; }
        public string MemberCity { get; set; }
        public int MemberPhone { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }
}
