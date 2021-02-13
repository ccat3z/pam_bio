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
        public virtual async bool preauth(Cancellable? cancellable = null)  throws IOError.CANCELLED {
            return true;
        }
        public abstract async AuthenticateResult auth(Cancellable? cancellable = null) throws Error;
        public abstract string name { owned get; }
    }

    private async AuthNProvider[] check_authentications(
        AuthenticateContext ctx,
        AuthNProvider[] available,
        Cancellable? cancellable
    ) throws IOError.CANCELLED {
        AuthNProvider[] result = new AuthNProvider[available.length];
        int i = 0;
        foreach (var authn in available) {
            if (ctx.modules.contains(authn.name)) {
                if (yield authn.preauth(cancellable)) {
                    result[i++] = authn;
                }
            }
        }
        result.resize(i);
        return result;
    }

    private async AuthenticateResult authenticate(
        PamHandler pamh, AuthenticateFlags flags, string[] argv
    ) {
        // prepare cancellable
        var cancellable = new Cancellable();
        Unix.signal_add(Posix.Signal.INT, () => {
           cancellable.cancel();
           return Source.REMOVE;
        });

        // TODO: may cause gnome shell freeze
        // Handle SIGTERM may cause gnome shell (polkit)
        // to freeze for a few seconds.
        // I have not idea on what cause this issue.
        // Since cleanup seems not necessay, I commented out the handler.
        //
        // Unix.signal_add(Posix.Signal.TERM, () => {
        //     cancellable.cancel();
        //     return Source.REMOVE;
        // });

        // prepare context
        var ctx = new AuthenticateContext(pamh, argv);
        if (!ctx.enable) return AuthenticateResult.AUTHINFO_UNAVAIL;

        // check authentications
        AuthNProvider[] authentications;
        try {
            authentications = yield check_authentications(
                ctx,
                new AuthNProvider[] {
                    #if ENABLE_FPRINT
                    new AuthNProviders.FprintAuthNProvider(ctx),
                    #endif
                    #if ENABLE_HOWDY
                    new AuthNProviders.HowdyAuthNProvider(ctx),
                    #endif
                    new AuthNProviders.PasswordAuthNProvider(ctx)
                },
                cancellable
            );
        } catch (IOError.CANCELLED e) {
            return AuthenticateResult.AUTH_ERR;
        }

        // do authenticate, run authenticate in parallel
        // return success, cred_insufficient or last authenticate result
        var wg = new WaitGroup();
        var res = AuthenticateResult.AUTHINFO_UNAVAIL;
        foreach (var authentication in authentications) {
            ctx.log(SysLogPriorities.DEBUG, authentication.name, "start");

            authentication.auth.begin(cancellable, (_, async_res) => {
                try {
                    AuthenticateResult auth_res = authentication.auth.end(async_res);
                    if (ctx.debug)
                        pamh.syslog(SysLogPriorities.DEBUG, @"$(authentication.name): auth result: $auth_res");

                    // ignore this result if authenticate already successed
                    if (res != AuthenticateResult.SUCCESS) {
                        switch (res = auth_res) {
                        // Cancel other auth task if success or cred insufficient
                        case AuthenticateResult.SUCCESS:
                        case AuthenticateResult.CRED_INSUFFICIENT:
                            Idle.add(() => { cancellable.cancel(); return Source.REMOVE; });
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

                wg.finish_cb();
            });
        }
        yield wg.wait_n(authentications.length);

        return res;
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