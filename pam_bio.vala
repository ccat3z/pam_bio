using Pam;
using Gee;

namespace PamBio {
    class AuthenticateContext : GLib.Object {
        public unowned PamHandler pamh { get; private set; }

        public AuthenticateContext(PamHandler pamh, string[] args) {
            this.pamh = pamh;
            merge_argv(args);
        }

        // options
        public bool debug = false;
        public bool enable_ssh = false;
        public bool enable_closed_lid = false;
        public Set<string> modules = new HashSet<string>();

        // computed properties

        public string username {
            get {
                weak string u;
                pamh.get_user(out u, null);
                return u;
            }
        }

        public bool enable {
            get {
                var envp = Environ.get();

                if (!enable_ssh) {
                    if (
                        Environ.get_variable(envp, "SSH_CONNECTION") != null ||
                        Environ.get_variable(envp, "SSH_CLIENT") != null ||
                        Environ.get_variable(envp, "SSHD_OPTS") != null
                    ) {
                        return false;
                    }
                }

                if (!enable_closed_lid) {
                    var g = Posix.Glob();
                    g.glob("/proc/acpi/button/lid/*/state");
                    foreach (var path in g.pathv) {
                        if (path.contains("closed")) {
                            return false;
                        }
                    }
                }

                return true;
            }
        }

        // help methods

        public void log(SysLogPriorities priority, string? prefix, string msg) {
            if (this.debug || priority <= SysLogPriorities.ERR) {
                if (prefix != null) {
                    this.pamh.syslog(priority, "%s: %s", prefix, msg);
                } else {
                    this.pamh.syslog(priority, "%s", msg);
                }
            }
        }

        private void merge_argv(string[] argv) {
            foreach (var arg in argv) {
                string[] kv = arg.split("=", 2);
                string key = kv[0];
                string? value = kv.length > 1 ? kv[1] : null;

                switch (key) {
                case "debug":
                    debug = true;
                    break;
                case "enable_ssh":
                    enable_ssh = true;
                    break;
                case "enable_closed_lid":
                    enable_closed_lid = true;
                    break;
                case "modules":
                    modules.add_all_array(value.split(","));
                    break;
                default:
                    pamh.syslog(SysLogPriorities.WARNING, @"unknown arg: $key");
                    break;
                }
            }
        }
    }

    interface AuthNProvider : GLib.Object {
        public abstract async AuthenticateResult auth(Cancellable? cancellable = null) throws Error;
        public abstract string name { owned get; }
    }

    private async AuthenticateResult authenticate(
        PamHandler pamh, AuthenticateFlags flags, string[] argv
    ) {
        var cancellable = new Cancellable();
        var ctx = new AuthenticateContext(pamh, argv);
        if (!ctx.enable) return AuthenticateResult.AUTHINFO_UNAVAIL;

        try {
            ctx.log(SysLogPriorities.INFO, null, "pam_bio started");

            var provider = new AuthNProviders.ParallelAuthNProvider(
                ctx,
                new AuthNProvider[] {
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