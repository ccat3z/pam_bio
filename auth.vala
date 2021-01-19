using Pam;
using Gee;

namespace PamBio {
    class AuthenticateContext : GLib.Object {
        public unowned PamHandler pamh;
        public bool debug = false;
        public bool enable_ssh { get; private set; default = false; }
        public bool enable_closed_lid { get; private set; default = false; }
        public bool enable_fprint { get; private set; default = true; }
        public bool enable_howdy { get; private set;  default = true; }

        public string username {
            get {
                weak string u;
                pamh.get_user(out u, null);
                return u;
            }
        }

        public void conv_info(string msg) {
            this.pamh.prompt(MessageStyle.TEXT_INFO, null, msg);
        }

        public void conv_err(string msg) {
            this.pamh.prompt(MessageStyle.ERROR_MSG, null, msg);
        }

        public void log_debug(string msg) {
            if (this.debug)
                this.pamh.syslog(SysLogPriorities.DEBUG, msg);
        }

        public void log_err(string msg) {
            this.pamh.syslog(SysLogPriorities.ERR, msg);
        }

        public void merge_argv(string[] argv) {
            // parser argv
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
                case "disable_howdy":
                    enable_howdy = false;
                    break;
                case "disable_fprint":
                    enable_fprint = false;
                    break;
                default:
                    pamh.syslog(SysLogPriorities.WARNING, @"unknown arg: $key");
                    break;
                }
            }

            // options side effect
            var envp = Environ.get();
            if (!enable_ssh) {
                if (
                    Environ.get_variable(envp, "SSH_CONNECTION") != null ||
                    Environ.get_variable(envp, "SSH_CLIENT") != null ||
                    Environ.get_variable(envp, "SSHD_OPTS") != null
                ) {
                    enable_fprint = false;
                    enable_howdy = false;
                }
            }

            if (!enable_closed_lid) {
                var g = Posix.Glob();
                g.glob("/proc/acpi/button/lid/*/state");
                foreach (var path in g.pathv) {
                    if (path.contains("closed")) {
                        enable_fprint = false;
                        enable_howdy = false;
                        break;
                    }
                }
            }
        }
    }

    interface Authentication : GLib.Object {
        public abstract async AuthenticateResult auth(Cancellable? cancellable = null) throws Error;
        public abstract string name { owned get; }
    }

    private async AuthenticateResult do_authenticate_async(PamHandler pamh, AuthenticateFlags flags, string[] argv) {
        var res = AuthenticateResult.AUTH_ERR;
        var res_mutex = Mutex();

        var ctx = new AuthenticateContext();
        ctx.pamh = pamh;
        ctx.merge_argv(argv);

        var authentications = new ArrayList<Authentication>();
        authentications.add(new PasswordAuthencation(ctx));

        #if ENABLE_FPRINT
        if (ctx.enable_fprint) {
            authentications.add(new Fprint.FprintAuthentication(ctx));
        }
        #endif
        #if ENABLE_HOWDY
        if (ctx.enable_howdy) {
            authentications.add(new Howdy.HowdyAuthencation(ctx));
        }
        #endif

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

        foreach (var authentication in authentications) {
            if (ctx.debug)
                pamh.syslog(SysLogPriorities.DEBUG, @"$(authentication.name): start");

            authentication.auth.begin(cancellable, (_, async_res) => {
                res_mutex.lock();

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
                    if (ctx.debug)
                        pamh.syslog(SysLogPriorities.DEBUG, @"$(authentication.name): cancelled");
                } catch (Error e) {
                    pamh.syslog(SysLogPriorities.ERR, @"$(authentication.name): unexcepted failed: $(e.domain) $(e.message)");
                }

                do_authenticate_async.callback();
                res_mutex.unlock();
            });
        }

        // wait all auth task
        for (var i = 0; i < authentications.size; i++) {
            yield;
        }

        return res;
    }

    [CCode(cname = "do_authenticate")]
    public AuthenticateResult do_authenticate(
        PamHandler pamh, AuthenticateFlags flags,
        [CCode(array_length_pos = 2, array_length_cname = "argc")]
        string[] argv
    ) {
        var loop = new MainLoop();
        AuthenticateResult auth_result = AuthenticateResult.AUTH_ERR;
        do_authenticate_async.begin(pamh, flags, argv, (obj, res) => {
            auth_result = do_authenticate_async.end(res);
            loop.quit();
        });
        loop.run();
        return auth_result;
    }
}