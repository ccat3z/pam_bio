using Pam;

namespace PamBio.AuthNProviders {
    class HowdyAuthNProvider : Object, AuthNProvider {
        private AuthenticateContext ctx;

        public HowdyAuthNProvider(AuthenticateContext ctx) {
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
            
            var cancelSource = new CancellableSource(cancellable);
            cancelSource.set_callback(_ => {
                proc.send_signal(Posix.Signal.INT);
                return Source.REMOVE;
            });
            cancelSource.attach();

            try {
                yield proc.wait_check_async();
                var exit = proc.get_exit_status();
                ctx.log(SysLogPriorities.DEBUG, name, @"compare.py exit with $exit");
                ctx.prompt(MessageStyle.TEXT_INFO, null, "Face is recognized");
                return exit == 0 ? AuthenticateResult.SUCCESS : AuthenticateResult.AUTH_ERR;
            } catch (GLib.Error e) {
                ctx.log(SysLogPriorities.WARNING, name, @"subprocess failed: $(e.domain): $(e.message)");
                return AuthenticateResult.AUTH_ERR;
            } finally {
                cancelSource.destroy();
            }
        }
    }
}