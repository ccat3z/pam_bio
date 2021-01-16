using Pam;

public class AuthenticateContext : GLib.Object {
    public unowned PamHandler pamh;
    public Cancellable cancellable;
    public bool debug = true;
    public string username {
        get {
            weak string u;
            pamh.get_user(out u, null);
            return u;
        }
    }

	public void conv_info(string msg) {
		Pam.Conversation.conv(this.pamh, Pam.MessageStyle.TEXT_INFO, msg);
	}

	public void conv_err(string msg) {
		Pam.Conversation.conv(this.pamh, Pam.MessageStyle.ERROR_MSG, msg);
	}

	public void log_debug(string msg) {
		if (this.debug)
			this.pamh.syslog_debug(msg);
	}

	public void log_err(string msg) {
		this.pamh.syslog_err(msg);
	}
}

public interface Authentication : GLib.Object {
    public abstract async AuthenticateResult auth(Cancellable? cancellable = null) throws Error;
}

private async AuthenticateResult do_authenticate_async(PamHandler pamh, AuthenticateFlags flags, string[] argv) {
    var res = AuthenticateResult.AUTH_ERR;
    var res_mutex = Mutex();

    var ctx = new AuthenticateContext();
    ctx.pamh = pamh;

    Authentication[] authentications = {
        new net.reactivated.Fprint.FprintAuthentication(ctx),
        new com.github.boltgolt.HowdyAuthencation(ctx),
    };

    var cancellable = new Cancellable();
    Unix.signal_add(Posix.Signal.INT, () => {
        cancellable.cancel();
        return Source.REMOVE;
    });

    foreach (var authentication in authentications) {
        authentication.auth.begin(cancellable, (_, async_res) => {
            res_mutex.lock();

            // ignore this result if authenticate already successed
            if (res != AuthenticateResult.SUCCESS) {
                try {
                    // cancel other auth task if success
                    if ((res = authentication.auth.end(async_res)) == AuthenticateResult.SUCCESS) {
                        Idle.add(() => { cancellable.cancel(); return Source.REMOVE; });
                    }
                } catch (Error e) {
                    pamh.syslog_err(e.message);
                }
            }

            do_authenticate_async.callback();
            res_mutex.unlock();
        });
    }

    // wait all auth task
    for (var i = 0; i < authentications.length; i++) {
        yield;
    }

    return res;
}

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