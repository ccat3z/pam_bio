#pragma once
#include <security/pam_ext.h>

typedef void (*pam_get_authtok_cb)(int result, const char *authtok, const void *data);
unsigned long pam_get_authtok_async(pam_handle_t *pamh, int item, const char *prompt, pam_get_authtok_cb callback, const void *callback_data);