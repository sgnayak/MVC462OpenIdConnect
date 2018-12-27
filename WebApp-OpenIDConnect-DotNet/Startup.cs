// <AddedNameSpaces>
using Microsoft.Owin;
using Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Microsoft.Owin.Security.Notifications;
using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;
// </AddedNameSpaces>

[assembly: OwinStartup(typeof(WebApp_OpenIDConnect_DotNet.Startup))]

namespace WebApp_OpenIDConnect_DotNet
{
    // <Startup>
    public class Startup
    {
        // The Client ID (a.k.a. Application ID) is used by the application to uniquely identify itself to Azure AD
        readonly string _clientId = System.Configuration.ConfigurationManager.AppSettings["ClientId"];

        // RedirectUri is the URL where the user will be redirected to after they sign in
        readonly string _redirectUrl = System.Configuration.ConfigurationManager.AppSettings["redirectUrl"];

        // Tenant is the tenant ID (e.g. contoso.onmicrosoft.com, or 'common' for multi-tenant)

        //Secret
        static readonly string Secret = System.Configuration.ConfigurationManager.AppSettings["Secret"];

        // Authority is the URL for authority, composed by Azure Active Directory endpoint and the tenant name (e.g. https://login.microsoftonline.com/contoso.onmicrosoft.com)
        readonly string _authority = String.Format(System.Globalization.CultureInfo.InvariantCulture, System.Configuration.ConfigurationManager.AppSettings["Authority"]);

        /// <summary>
        /// Configure OWIN to use OpenIdConnect 
        /// </summary>
        /// <param name="app"></param>
        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    ClientId = _clientId,
                    ClientSecret = Secret,
                    Authority = _authority,
                    RedirectUri = _redirectUrl,
                    //CallbackPath = new PathString("/authorization-code/callback"),
                    ResponseType = OpenIdConnectResponseType.CodeIdToken,
                    Scope = OpenIdConnectScope.OpenIdProfile,
                    UseTokenLifetime = false,

                    SignInAsAuthenticationType = "Cookies",

                    // ValidateIssuer set to false to allow work accounts from any organization to sign in to your application
                    // To only allow users from a single organizations, set ValidateIssuer to true and 'tenant' setting in web.config to the tenant name or Id (example: contoso.onmicrosoft.com)
                    // To allow users from only a list of specific organizations, set ValidateIssuer to true and use ValidIssuers parameter
                    TokenValidationParameters = new TokenValidationParameters()
                    {
                        ValidateIssuer = false
                    },

                    // OpenIdConnectAuthenticationNotifications configures OWIN to send notification of failed authentications to OnAuthenticationFailed method
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        AuthenticationFailed = OnAuthenticationFailed,

                        RedirectToIdentityProvider = (context) =>
                        {
                            Debug.WriteLine("*** RedirectToIdentityProvider");
                            return Task.FromResult(0);
                        },
                        MessageReceived = (context) =>
                        {
                            Debug.WriteLine("*** MessageReceived");
                            return Task.FromResult(0);
                        },
                        SecurityTokenReceived = (context) =>
                        {
                            Debug.WriteLine("*** SecurityTokenReceived");
                            return Task.FromResult(0);
                        },
                        SecurityTokenValidated = (context) =>
                        {
                            Debug.WriteLine("*** SecurityTokenValidated");
                            return Task.FromResult(0);
                        },
                        AuthorizationCodeReceived = (context) =>
                        {
                            Debug.WriteLine("*** AuthorizationCodeReceived");
                            return Task.FromResult(0);
                        },
                    }

                }
            );
        }

        /// <summary>
        /// Handle failed authentication requests by redirecting the user to the home page with an error in the query string
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        private Task OnAuthenticationFailed(AuthenticationFailedNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            context.HandleResponse();
            context.Response.Redirect("/?errormessage=" + context.Exception.Message);
            return Task.FromResult(0);
        }
    }
    // </Startup>
}
