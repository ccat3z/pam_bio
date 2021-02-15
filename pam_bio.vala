using Pam;

namespace PamBio {
    private async AuthenticateResult authenticate(
        PamHandler pamh, AuthenticateFlags flags, string[] argv
    ) {
        var cancellable = new Cancellable();

        var config = new Config();
        try {
            config.from_argv(argv);
        } catch (Error e) {
            pamh.syslog(SysLogPriorities.ERR, @"pam_bio failed: $(e.domain) $(e.message)");
            return AuthenticateResult.AUTH_ERR;
        }

        var ctx = new AuthenticateContext(pamh, config);
        if (!ctx.enable) return AuthenticateResult.AUTHINFO_UNAVAIL;

        try {
            ctx.log(SysLogPriorities.INFO, null, "pam_bio started");

            var provider = new AuthNProviders.ParallelAuthNProvider(
                ctx,
                new AuthNProviders.AuthNProvider[] {
                    #if ENABLE_FPRINT
                    new AuthNProviders.FprintAuthNProvider(ctx),
                    #endif
                    #if ENABLE_HOWDY
                    new AuthNProviders.HowdyAuthNProvider(ctx),
                    #endif
                    new AuthNProviders.PasswordAuthNProvider(ctx)
                }
            );
            var res = yield provider.auth(cancellable);
            ctx.log(SysLogPriorities.INFO, null, @"pam_bio $res");
            return res;
        } catch (Error e) {
            ctx.log(SysLogPriorities.ERR, null, @"pam_bio failed: $(e.domain) $(e.message)");
            return AuthenticateResult.AUTH_ERR;
        } finally {
            cancellable.cancel();
        }
    }

    [CCode(cname = "do_authenticate")]
    public AuthenticateResult do_authenticate(
        PamHandler pamh, AuthenticateFlags flags,
        [CCode(array_length_pos = 2, array_length_cname = "argc")]
        string[] argv
    ) {
        var loop = new MainLoop();
        AuthenticateResult auth_result = AuthenticateResult.AUTHINFO_UNAVAIL;
        authenticate.begin(pamh, flags, argv, (obj, res) => {
            auth_result = authenticate.end(res);
            loop.quit();
        });
        loop.run();
        return auth_result;
    }
}