using Pam;

namespace PamBio.AuthNProviders {
    interface AuthNProvider : GLib.Object {
        public abstract async AuthenticateResult auth(Cancellable? cancellable = null) throws Error;
        public abstract string name { owned get; }
    }
}