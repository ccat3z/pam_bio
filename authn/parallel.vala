using Pam;

namespace PamBio.AuthNProviders {
    class ParallelAuthNProvider : GLib.Object, AuthNProvider {
        private AuthNProvider[] providers;
        private AuthenticateContext ctx;

        public ParallelAuthNProvider(AuthenticateContext ctx, AuthNProvider[] providers) {
            this.ctx = ctx;
            this.providers = providers;
        }

        public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
            var res = AuthenticateResult.AUTHINFO_UNAVAIL;
            var providerCancellable = new Cancellable();
            var cancelSource = new CancellableSource(cancellable);
            cancelSource.set_callback(_ => {
                providerCancellable.cancel();
                return Source.REMOVE;
            });
            cancelSource.attach();

            foreach (var authentication in providers) {
                ctx.log(SysLogPriorities.DEBUG, authentication.name, "start");

                authentication.auth.begin(providerCancellable, (_, async_res) => {
                    try {
                        AuthenticateResult auth_res = authentication.auth.end(async_res);
                        ctx.log(SysLogPriorities.DEBUG, authentication.name, @"auth result: $auth_res");

                        // ignore this result if authenticate already successed
                        if (res != AuthenticateResult.SUCCESS) {
                            switch (res = auth_res) {
                            // Cancel other auth task if success or cred insufficient
                            case AuthenticateResult.SUCCESS:
                            case AuthenticateResult.CRED_INSUFFICIENT:
                                providerCancellable.cancel();
                                break;
                            default:
                                break;
                            }
                        }
                    } catch (IOError.CANCELLED cancel) {
                        ctx.log(SysLogPriorities.DEBUG, authentication.name, "cancelled");
                        if (
                            res != AuthenticateResult.SUCCESS
                            && res != AuthenticateResult.CRED_INSUFFICIENT
                        ) {
                            res = AuthenticateResult.AUTH_ERR;
                        }
                    } catch (Error e) {
                        ctx.log(SysLogPriorities.ERR, authentication.name, @"unexcepted failed: $(e.domain) $(e.message)");
                    }

                    auth.callback();
                });
            }

            for (int i = 0; i < providers.length; i++) yield;
            cancelSource.destroy();
            return res;
        }

        public string name { owned get { return "parallel"; } }
    }
}