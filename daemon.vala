using Pam;
using Gee;

namespace PamBio {
    class DaemonAuthenticateContext : GLib.Object, AuthenticateContext {
        public SourceFunc? resume;

        public Config config { get; protected set; }
        public string username { get { return _username; } }
        private string _username;
        public delegate void PromptMessageFunc(string msg, bool err);
        private PromptMessageFunc prompt_func;
        public delegate void CancelFunc();
        public CancelFunc cancel_func;

        public DaemonAuthenticateContext(
            string username,
            Config config,
            owned PromptMessageFunc prompt_func,
            owned CancelFunc cancel_func
        ) {
            this.config = config;
            this._username = username;
            this.prompt_func = (owned) prompt_func;
            this.cancel_func = (owned) cancel_func;
        }

        public void log(SysLogPriorities priority, string? prefix, string msg) {
            var m = msg;
            if (prefix != null) {
                m = @"$prefix: $m";
            }

            switch (priority) {
            case SysLogPriorities.EMERG:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_CRITICAL, m);
                break;
            case SysLogPriorities.ALERT:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_CRITICAL, m);
                break;
            case SysLogPriorities.CRIT:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_CRITICAL, m);
                break;
            case SysLogPriorities.ERR:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_CRITICAL, m);
                break;
            case SysLogPriorities.WARNING:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_WARNING, m);
                break;
            case SysLogPriorities.NOTICE:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_MESSAGE, m);
                break;
            case SysLogPriorities.INFO:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_INFO, m);
                break;
            case SysLogPriorities.DEBUG:
                GLib.log(Build.LOG_TAG, LogLevelFlags.LEVEL_DEBUG, m);
                break;
            default:
                critical("Should never reach here");
                break;
            }
        }

        public void prompt(MessageStyle style, out string resp, string msg) {
            resp = null;

            switch (style) {
            case MessageStyle.PROMPT_ECHO_ON:
            case MessageStyle.PROMPT_ECHO_OFF:
                critical("not support prompt_echo yet");
                resp = "";
                break;
            case MessageStyle.TEXT_INFO:
                prompt_func(msg, false);
                break;
            case MessageStyle.ERROR_MSG:
                prompt_func(msg, true);
                break;
            default:
                critical("Should never reach here");
                break;
            }
        }

        public void cancel() {
            cancel_func();
        }
    }


	[DBus(name = "xyz.ccat3z.pambio")]
	class DaemonImpl : GLib.Object {
        private org.freedesktop.DBus dbus = null;
        private Config config = null;
        private HashMap<string, DaemonAuthenticateContext> clients = new HashMap<string, DaemonAuthenticateContext>();
        private ArrayQueue<DaemonAuthenticateContext> pending = new ArrayQueue<DaemonAuthenticateContext>();
        private Mutex auth_mutex;

        [DBus(visible = false)]
        public async void on_start() throws Error {
			this.dbus = yield Bus.get_proxy(BusType.SYSTEM, "org.freedesktop.DBus", "/org/freedesktop/DBus");
            this.dbus.name_owner_changed.connect((name, _, n) => {
                if (n == "") {
                    on_bus_name_disapper(name);
                }
            });
            config = new Config();
            debug("PamBio daemon ready");
        }

        private void on_bus_name_disapper(string name) {
            DaemonAuthenticateContext ctx;
            clients.unset(name, out ctx);
            if (ctx != null) {
                debug(@"client $name disappeared");
                ctx.cancel();
            }
        }

        private async AuthenticateResult authenticate_by_ctx(DaemonAuthenticateContext ctx, Cancellable? cancellable) throws Error {
            var auth = new AuthNProviders.ParallelAuthNProvider(
                ctx,
                new AuthNProviders.AuthNProvider[] {
                    new AuthNProviders.FprintAuthNProvider(ctx),
                    new AuthNProviders.HowdyAuthNProvider(ctx)
                }
            );
            return yield auth.auth(cancellable);
        }

        public async AuthenticateResult authenticate(string username, BusName sender) throws Error {
            var cancellable = new Cancellable();
            var ctx = new DaemonAuthenticateContext(
                username,
                config,
                (m, e) => prompt(m, e),
                cancellable.cancel
            );
            assert(!clients.has_key(sender));

            try {
                clients[sender] = ctx;
                while (!auth_mutex.trylock()) {
                    debug(@"$sender waiting for other authentication processes to finish");
                    ctx.resume = authenticate.callback;
                    pending.add(ctx);
                    yield;
                }
                debug(@"$sender authentication start");

                var res = yield authenticate_by_ctx(ctx, cancellable);
                debug(@"$sender authentication finished ($res)");
                return res;
            } catch (Error e) {
                warning(@"$sender authentication failed: $(e.domain) $(e.message)");
                throw e;
            } finally {
                clients.unset(sender);
                var next = pending.poll();
                if (next != null) Idle.add((owned) next.resume);
                auth_mutex.unlock();
            }
        }

        public signal void prompt(string msg, bool err);
	}
}

int main() {
    var loop = new MainLoop();
    Idle.add(() => {
        var daemon = new PamBio.DaemonImpl();

        Bus.own_name(BusType.SYSTEM, "xyz.ccat3z.pambio", BusNameOwnerFlags.NONE,
            (conn) => {
                try {
                    conn.register_object("/xyz/ccat3z/pambio", daemon);
                } catch (IOError e) {
                    critical("Could not register service\n");
                }
            },
            () => {
                daemon.on_start.begin((_, res) => {
                    try {
                        daemon.on_start.end(res);
                    } catch (Error e) {
                        critical(@"Failed to start daemon: $(e.domain) $(e.message)\n");
                        loop.quit();
                    }
                });
            },
            () => {
                critical("Could not aquire name\n");
                loop.quit();
            }
        );
        return Source.REMOVE;
    });
    loop.run();
    return 1;
}