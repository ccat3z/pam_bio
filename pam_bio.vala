using Pam;

namespace PamBio {
    class PamAuthenticateContext : GLib.Object, AuthenticateContext {
        public unowned PamHandler pamh { get; private set; }
        public Config config { get; protected set; }

        public PamAuthenticateContext(PamHandler pamh, Config config) {
            this.pamh = pamh;
            this.config = config;
        }

        public string username {
            get {
                weak string u;
                pamh.get_user(out u, null);
                return u;
            }
        }

        public void log(SysLogPriorities priority, string? prefix, string msg) {
            if (this.config.debug || priority <= SysLogPriorities.ERR) {
                if (prefix != null) {
                    this.pamh.syslog(priority, "%s: %s", prefix, msg);
                } else {
                    this.pamh.syslog(priority, "%s", msg);
                }
            }
        }

        public void prompt(MessageStyle style, out string resp, string message) {
            pamh.prompt(style, out resp, message);
        }
    }

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

        if (!config.enable) return AuthenticateResult.AUTHINFO_UNAVAIL;

        var ctx = new PamAuthenticateContext(pamh, config);

        try {
            ctx.log(SysLogPriorities.INFO, null, "pam_bio started");

            var provider = new AuthNProviders.ParallelAuthNProvider(
                ctx,
                new AuthNProviders.AuthNProvider[] {
                    new AuthNProviders.DaemonAuthNProvider(ctx),
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