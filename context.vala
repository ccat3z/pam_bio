using Gee;
using Pam;

namespace PamBio {
    interface AuthenticateContext : GLib.Object {
        public abstract Config config { get; protected set; }
        public abstract string username { get; }
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

        public abstract void log(SysLogPriorities priority, string? prefix, string messsage);
        public abstract void prompt(MessageStyle style, out string resp, string message);
    }
}