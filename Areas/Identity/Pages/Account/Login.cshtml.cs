using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using MimeKit;
using MimeKit.Text;
//using System.Net.Mail;
using System.Net;
using System.Net.Mime;
using MailKit.Net.Smtp;

namespace RuperMurder.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class LoginModel : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ILogger<LoginModel> _logger;

        public LoginModel(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager, ILogger<LoginModel> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl = returnUrl ?? Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl = returnUrl ?? Url.Content("~/");

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    return LocalRedirect(returnUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    
                    //MailMessage mailMessage = new MailMessage();
                    //mailMessage.To.Add(Input.Email);
                    //mailMessage.From = new MailAddress("mamudseun@gmail.com");
                    //mailMessage.Subject = "Login Error";
                    //mailMessage.Body = "Lorem Ipsum je fiktívny text, používaný pri návrhu tlačovín a typografie. " +
                    //    "Lorem Ipsum je štandardným výplňovým textom už od 16. storočia, keď neznámy tlačiar zobral sadzobnicu plnú tlačových znakov a pomiešal ich, " +
                    //    "aby tak vytvoril vzorkovú knihu. Prežil nielen päť storočí, ale aj skok do elektronickej sadzby, a pritom zostal v podstate nezmenený.";
                    //SmtpClient smtpClient = new SmtpClient("smtp.office365.com", 587);

                    //smtpClient.Send(mailMessage);


                    var message = new MimeMessage();

                    message.To.Add(new MailboxAddress(Input.Email));
                    message.From.Add(new MailboxAddress("RuperMurder", "mamudseun@gmail.com"));

                    message.Subject = "Login Error";

                    message.Body = new TextPart(TextFormat.Html)
                    {
                        Text = "<p>Lorem Ipsum je fiktívny text, používaný pri návrhu tlačovín a typografie. " +
                        "Lorem Ipsum je štandardným výplňovým textom už od 16. storočia, keď neznámy tlačiar zobral sadzobnicu plnú tlačových znakov a pomiešal ich, " +
                        "aby tak vytvoril vzorkovú knihu. Prežil nielen päť storočí, ale aj skok do elektronickej sadzby, a pritom zostal v podstate nezmenený.</p>"
                    };

                    

                    using (var emailClient = new SmtpClient())
                    {
                        emailClient.ServerCertificateValidationCallback = (sender, certificate, certChainType, errors) => true;
                        emailClient.AuthenticationMechanisms.Remove("XOAUTH2");

                        emailClient.Connect("smtp.office365.com", 587, false);
                        //needs authenticated email address
                        emailClient.Authenticate("mamudseun@gmail.com", "*********");
                        emailClient.Send(message);
                        emailClient.Disconnect(true);
                    }
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }
    }
}
