[CCode(cheader_filename = "security/pam_modules.h,sys/syslog.h")]
namespace Pam {
    [CCode(cname = "pam_handle_t", cprefix = "pam_")]
    [Compact]
    public class PamHandler {
        public void *get_item(ItemType item_type, out void *item);
        public int get_user(out unowned string user, out string prompt);	 
        public int syslog(SysLogPriorities priority, string fmt, ...);
        public int syslog_debug(string msg) {
            return this.syslog(SysLogPriorities.DEBUG, msg);
        }
        public int syslog_info(string msg) {
            return this.syslog(SysLogPriorities.INFO, msg);
        }
        public int syslog_err(string msg) {
            return this.syslog(SysLogPriorities.ERR, msg);
        }
    }

    [CCode(cname = "struct pam_message")]
    public struct PamMessage {
        int msg_style;
        char *msg;
    }

    [CCode(cname = "struct pam_response")]
    public struct PamResponse {
        char *resp;
        int resp_retcode;
    }

    [CCode(cname = "struct pam_conv")]
    public struct PamConv {
        void *conv;
        void *appdata_ptr;
    }

    [CCode(cname = "int", cprefix = "PAM_") ]
    public enum ItemType {
        SERVICE,
        USER,
        USER_PROMPT,
        TTY,
        RUSER,
        RHOST,
        AUTHTOK,
        OLDAUTHTOK,
        CONV,
        FAIL_DELAY,
        XDISPLAY,
        XAUTHDATA,
        AUTHTOK_TYPE
    }

    [CCode(cname = "int", cprefix = "PAM_") ]
    [Flags]
    public enum AuthenticateFlags {
        SILENT,
        DISALLOW_NULL_AUTHTOK
    }

    [CCode(cname = "int", cprefix = "PAM_") ]
    public enum AuthenticateResult {
        AUTH_ERR,
        CRED_INSUFFICIENT,
        AUTHINFO_UNAVAIL,
        SUCCESS,
        USER_UNKNOWN,
        MAXTRIES;

        public string to_string() {
            switch (this) {
            case AUTH_ERR:
                return "err";
            case CRED_INSUFFICIENT:
                return "cred insufficient";
            case AUTHINFO_UNAVAIL:
                return "authinfo unavail";
            case SUCCESS:
                return "success";
            case USER_UNKNOWN:
                return "user unknown";
            case MAXTRIES:
                return "max tries";
            default:
                GLib.assert_not_reached();
            }
        }
    }

    [CCode(cname = "int", cprefix = "PAM_")]
    public enum MessageStyle {
        PROMPT_ECHO_OFF,
        PROMPT_ECHO_ON,
        ERROR_MSG,
        TEXT_INFO
    }

    [CCode(cname = "int", cprefix = "LOG_")]
    public enum SysLogPriorities {
        EMERG,
        ALERT,
        CRIT,
        ERR,
        WARNING,
        NOTICE,
        INFO,
        DEBUG
    }
}