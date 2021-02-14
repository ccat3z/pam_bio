#pragma once
#include <security/pam_ext.h>
#include <gio/gio.h>

void pam_get_authtok_async (
    pam_handle_t *pamh, int item, const char *prompt,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data
);

int pam_get_authtok_finish (
    pam_handle_t *pamh,
    GAsyncResult *result,
    const char** authtok,
    GError **error
);