[CCode(cheader_filename = "security/pam_modules.h")]
namespace Pam {
    [CCode(cname = "pam_handle_t", cprefix = "pam_")]
    public class PamHandler {
    }

    [CCode (cname = "int", cprefix = "PAM_") ]
    [Flags]
    public enum AuthenticateFlags {
        SILENT,
        DISALLOW_NULL_AUTHTOK
    }

    [CCode (cname = "int", cprefix = "PAM_") ]
    public enum AuthenticateResult {
        AUTH_ERR,
        CRED_INSUFFICIENT,
        AUTHINFO_UNAVAIL,
        SUCCESS,
        USER_UNKNOWN,
        MAXTRIES
    }
}