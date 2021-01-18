#include "pam_async_ext.h"
#include <pthread.h>
#include <stdlib.h>

typedef struct {
    pam_handle_t *pamh;
    int item;
    pam_get_authtok_cb callback;
    const void *callback_data;
    const char *prompt;
} pam_get_authtok_data_t;

static void *pam_get_authtok_thread(void *d) {
    pam_get_authtok_data_t *data = (pam_get_authtok_data_t *) d;
    const char *authtok;
    int res = pam_get_authtok(data->pamh, data->item, &authtok, data->prompt);
    data->callback(res, authtok, data->callback_data);

    free(data);
    pthread_exit(NULL);
}

void pam_get_authtok_cancel(unsigned long t) {
    pthread_cancel(t);
}

unsigned long pam_get_authtok_async(pam_handle_t *pamh, int item, const char *prompt, pam_get_authtok_cb callback, const void *callback_data) {
    pthread_t thread;

    pam_get_authtok_data_t *data = malloc(sizeof(pam_get_authtok_data_t));
    data->pamh = pamh;
    data->item = item;
    data->callback = callback;
    data->prompt = prompt;
    data->callback_data = callback_data;
    
    pthread_create(&thread, NULL, pam_get_authtok_thread, data);
    return thread;
}