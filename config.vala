using Gee;

namespace PamBio {
    errordomain ConfigError {
        INVALID_KEY
    }

    class Config : GLib.Object {
        public bool debug = false;
        public bool enable_ssh = false;
        public bool enable_closed_lid = false;
        public Set<string> modules = new HashSet<string>();

        public void from_argv(string[] argv) throws ConfigError {
            foreach (var arg in argv) {
                string[] kv = arg.split("=", 2);
                string key = kv[0];
                string? value = kv.length > 1 ? kv[1] : null;

                switch (key) {
                case "debug":
                    debug = true;
                    break;
                case "enable_ssh":
                    enable_ssh = true;
                    break;
                case "enable_closed_lid":
                    enable_closed_lid = true;
                    break;
                case "modules":
                    modules.add_all_array(value.split(","));
                    break;
                default:
                    throw new ConfigError.INVALID_KEY(@"unknow key: $key");
                }
            }
        }
    }
}
