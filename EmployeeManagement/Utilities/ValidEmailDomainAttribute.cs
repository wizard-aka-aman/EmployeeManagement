using System.ComponentModel.DataAnnotations;

namespace EmployeeManagement.Utilities
{
    public class ValidEmailDomainAttribute : ValidationAttribute
    {
        private readonly string allowedDomain;

        public ValidEmailDomainAttribute(string allowedDomain)
        {
            this.allowedDomain = allowedDomain;
        }

        //public override bool IsValid1(object value)
        //{
        //    if (value == null || !(value is string email) || !email.Contains("@"))
        //        return false;
        //    string[] strings = value.ToString().Split('@');
        //    return strings[1].ToUpper() == allowedDomain.ToUpper();
        //}
        public override bool IsValid(object value)
        {
            if (value == null || !(value is string email) || !email.Contains("@"))
                return false;

            string[] parts = email.ToString().Split('@');
            return parts[1].ToUpper() == allowedDomain.ToUpper();
            //return parts.Length > 1 && parts[1].Equals(allowedDomain, StringComparison.OrdinalIgnoreCase);
        }
    }
}
