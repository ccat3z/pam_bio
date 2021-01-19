using Pam;

namespace PamBio.Howdy {
    class HowdyAuthencation : Object, Authentication {
        private AuthenticateContext ctx;

        public HowdyAuthencation(AuthenticateContext ctx) {
            this.ctx = ctx;
        }

        public string name { owned get { return "howdy"; } }

        private async void redirect_input_stream(InputStream inputStream, SysLogPriorities priority) throws IOError {
            var data = new DataInputStream(inputStream);
            string? line;
            while ((line = yield data.read_line_utf8_async()) != null) {
                ctx.log(priority, name, @"$line");
            }
        }

        public async AuthenticateResult auth(Cancellable? cancellable = null) throws Error {
            var proc = new Subprocess(SubprocessFlags.STDERR_PIPE | SubprocessFlags.STDOUT_PIPE, "python", Build.HOWDY_COMPARE, ctx.username);
            redirect_input_stream.begin(proc.get_stdout_pipe(), SysLogPriorities.DEBUG);
            redirect_input_stream.begin(proc.get_stderr_pipe(), SysLogPriorities.WARNING);
            
            ulong cancel_sig = 0;
            if (cancellable != null) {
                cancel_sig = cancellable.connect(() => {
                    proc.send_signal(Posix.Signal.INT);
                });
            }

            try {
                yield proc.wait_check_async();
                var exit = proc.get_exit_status();
                ctx.log(SysLogPriorities.DEBUG, name, @"compare.py exit with $exit");
                ctx.pamh.prompt(MessageStyle.TEXT_INFO, null, "Face is recognized");
                return exit == 0 ? AuthenticateResult.SUCCESS : AuthenticateResult.AUTH_ERR;
            } catch (GLib.Error e) {
                ctx.log(SysLogPriorities.WARNING, name, @"subprocess failed: $(e.domain): $(e.message)");
                return AuthenticateResult.AUTH_ERR;
            } finally {
                cancellable.disconnect(cancel_sig);
            }
        }
    }
}