using Pam;

namespace PamBio {
	[DBus (name = "xyz.ccat3z.pambio", timeout = 120000)]
	interface Daemon : GLib.Object {
        public abstract async AuthenticateResult authenticate(string username, Cancellable? cancellable) throws Error;
        public signal void prompt(string msg, bool err);
	}
}
