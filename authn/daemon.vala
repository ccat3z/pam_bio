using Pam;
using PamBio;

namespace PamBio.AuthNProviders {
	class DaemonAuthNProvider : GLib.Object, AuthNProvider {
        private AuthenticateContext ctx;

        public DaemonAuthNProvider(AuthenticateContext ctx) {
            this.ctx = ctx;
        }

        public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
            var daemon = yield Bus.get_proxy<PamBio.Daemon>(BusType.SYSTEM, "xyz.ccat3z.pambio", "/xyz/ccat3z/pambio");
            daemon.prompt.connect((msg, err) => {
                ctx.prompt(err ? MessageStyle.ERROR_MSG : MessageStyle.TEXT_INFO, null, msg);
            });
            return yield daemon.authenticate(ctx.username, cancellable);
		}

        public string name { owned get { return "daemon"; } }
	}
}