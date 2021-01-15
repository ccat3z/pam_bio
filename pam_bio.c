#include <security/pam_modules.h>
#include <glib.h>

extern int do_authenticate (pam_handle_t* pamh, int flags, gint argc, gchar** argv);

PAM_EXTERN int pam_sm_authenticate (pam_handle_t* pamh, int flags, int argc, const char** argv) {

    return do_authenticate(pamh, flags, argc, argv);
}