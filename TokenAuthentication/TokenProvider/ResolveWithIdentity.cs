using System.Security.Claims;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using TokenAuthentication.Models;

namespace TokenAuthentication
{
    public class ResolveWithIdentity
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        public ResolveWithIdentity(SignInManager<ApplicationUser> signInManager)
        {
            _signInManager = signInManager;
        }

        public async Task<ClaimsIdentity> GetIdentity(string username, string password)
        {
            var result = await _signInManager.PasswordSignInAsync(username, password, false, lockoutOnFailure: false);
            if (result.Succeeded)
            {
                return await Task.FromResult(new ClaimsIdentity(new GenericIdentity(username, "Token"), new Claim[] { }));
            }
            if (result.RequiresTwoFactor)
            {
            }
            if (result.IsLockedOut)
            {
            }

            // Credentials are invalid, or account doesn't exist
            return await Task.FromResult<ClaimsIdentity>(null);
        }
    }
}
