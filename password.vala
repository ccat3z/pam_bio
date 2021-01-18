using Pam;

class PasswordAuthencation : Object, Authentication {
    private AuthenticateContext ctx;

    public PasswordAuthencation(AuthenticateContext ctx) {
        this.ctx = ctx;
    }

    public string name { owned get { return "pass"; } }

    public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
        weak string? tok = null;
        GetAuthTokResult res = GetAuthTokResult.AUTHTOK_ERR;

        Mutex cb_mutex = Mutex();
        var sig = ctx.pamh.get_authtok_async(GetAuthTokItem.AUTHTOK, null, (r, t) => {
            res = r;
            tok = t;
            if (cb_mutex.trylock()) Idle.add(auth.callback);
        });
        ulong cancel_sig = 0;
        if (cancellable != null) {
            cancel_sig = cancellable.connect(() => {
                ctx.pamh.get_authtok_cancel(sig);
                if (cb_mutex.trylock()) Idle.add(auth.callback);
            });
        }
        yield;
        cancellable.disconnect(cancel_sig);
        cb_mutex.unlock();

        if (tok != null) {
            ctx.log_debug(@"pass: got $tok");
            return AuthenticateResult.CRED_INSUFFICIENT;
        } else {
            if (!cancellable.is_cancelled())
                ctx.log_err("pass: failed to retrieve pass");
            return AuthenticateResult.AUTH_ERR;
        }
    }
}