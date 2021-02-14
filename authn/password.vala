using Pam;

namespace PamBio.AuthNProviders {
    class PasswordAuthNProvider : Object, AuthNProvider {
        private AuthenticateContext ctx;

        public PasswordAuthNProvider(AuthenticateContext ctx) {
            this.ctx = ctx;
        }

        public string name { owned get { return "pass"; } }

        public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
            weak string tok = null;
            yield ctx.pamh.get_authtok_async(GetAuthTokItem.AUTHTOK, null, cancellable, out tok);

            if (tok == null) {
                ctx.log(SysLogPriorities.ERR, name, "failed to retrieve pass");
                return AuthenticateResult.AUTH_ERR;
            }

            ctx.log(SysLogPriorities.DEBUG, name, "got authtok");
            return AuthenticateResult.CRED_INSUFFICIENT;
        }
    }
}