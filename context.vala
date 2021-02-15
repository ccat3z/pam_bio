using Gee;
using Pam;

namespace PamBio {
    interface AuthenticateContext : GLib.Object {
        public abstract Config config { get; protected set; }
        public abstract string username { get; }

        public abstract void log(SysLogPriorities priority, string? prefix, string messsage);
        public abstract void prompt(MessageStyle style, out string resp, string message);
    }
}