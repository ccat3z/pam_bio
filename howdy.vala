using Pam;

namespace com.github.boltgolt {
    class HowdyAuthencation : Object, Authentication {
        private AuthenticateContext ctx;

        public HowdyAuthencation(AuthenticateContext ctx) {
            this.ctx = ctx;
        }

        public string name { owned get { return "howdy"; } }

        private async void redirect_input_stream(InputStream inputStream) throws IOError {
            var data = new DataInputStream(inputStream);
            string? line;
            while ((line = yield data.read_line_utf8_async()) != null) {
                ctx.log_debug(@"howdy: $line");
            }
        }

        public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
            var proc = new Subprocess(SubprocessFlags.STDERR_PIPE, "python", Build.HOWDY_COMPARE, ctx.username);
            redirect_input_stream.begin(proc.get_stderr_pipe());
            
            ulong cancel_sig = 0;
            if (cancellable != null) {
                cancel_sig = cancellable.connect(() => {
                    proc.send_signal(Posix.Signal.INT);
                });
            }

            try {
                yield proc.wait_check_async();
                var exit = proc.get_exit_status();
                ctx.log_debug(@"howdy: compare.py exit with $exit");
                return exit == 0 ? AuthenticateResult.SUCCESS : AuthenticateResult.AUTH_ERR;
            } catch (GLib.Error e) {
                ctx.log_debug(@"hodwy: subprocess failed: $(e.domain): $(e.message)");
                return AuthenticateResult.AUTH_ERR;
            } finally {
                cancellable.disconnect(cancel_sig);
            }
        }
    }
}