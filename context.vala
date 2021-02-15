using Gee;
using Pam;

namespace PamBio {
    class AuthenticateContext : GLib.Object {
        public unowned PamHandler pamh { get; private set; }
        public Config config { get; private set; }

        public AuthenticateContext(PamHandler pamh, Config config) {
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

        public bool enable {
            get {
                var envp = Environ.get();

                if (!config.enable_ssh) {
                    if (
                        Environ.get_variable(envp, "SSH_CONNECTION") != null ||
                        Environ.get_variable(envp, "SSH_CLIENT") != null ||
                        Environ.get_variable(envp, "SSHD_OPTS") != null
                    ) {
                        return false;
                    }
                }

                if (!config.enable_closed_lid) {
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

        public void log(SysLogPriorities priority, string? prefix, string msg) {
            if (this.config.debug || priority <= SysLogPriorities.ERR) {
                if (prefix != null) {
                    this.pamh.syslog(priority, "%s: %s", prefix, msg);
                } else {
                    this.pamh.syslog(priority, "%s", msg);
                }
            }
        }
    }
}