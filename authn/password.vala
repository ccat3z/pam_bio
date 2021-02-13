using Pam;

namespace PamBio.AuthNProviders {
    class PasswordAuthNProvider : Object, AuthNProvider {
        private AuthenticateContext ctx;

        public PasswordAuthNProvider(AuthenticateContext ctx) {
            this.ctx = ctx;
        }

        public string name { owned get { return "pass"; } }

        public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
            weak string? tok = null;
            GetAuthTokResult res = GetAuthTokResult.AUTHTOK_ERR;

            var wg = new WaitGroup();

            var sig = ctx.pamh.get_authtok_async(GetAuthTokItem.AUTHTOK, null, (r, t) => {
                res = r;
                tok = t;
                wg.finish_cb();
            });
            ulong cancel_sig = 0;
            if (cancellable != null) {
                cancel_sig = cancellable.connect(() => {
                    ctx.pamh.get_authtok_cancel(sig);
                    wg.finish_cb();
                });
            }

            yield wg.wait_any();
            cancellable.disconnect(cancel_sig);

            if (tok != null) {
                ctx.log(SysLogPriorities.DEBUG, name, @"got authtok");
                return AuthenticateResult.CRED_INSUFFICIENT;
            } else {
                if (!cancellable.is_cancelled())
                    ctx.log(SysLogPriorities.ERR, name, "failed to retrieve pass");
                return AuthenticateResult.AUTH_ERR;
            }
        }
    }
}