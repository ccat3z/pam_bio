using Pam;

namespace com.github.boltgolt {
    class HowdyAuthencation : Object, Authentication {
        private AuthenticateContext ctx;

        public HowdyAuthencation(AuthenticateContext ctx) {
            this.ctx = ctx;
        }

        public string name { owned get { return "howdy"; } }

        public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
            yield nap(1000);
            return AuthenticateResult.SUCCESS;
        }
    }
}