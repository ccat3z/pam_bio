#include "pam_async_ext.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

typedef struct {
    pam_handle_t *pamh;
    int item;
    pam_get_authtok_cb callback;
    const void *callback_data;
    const char *prompt;
    pthread_t thread;
} pam_get_authtok_data_t;

static void free_pam_get_authtok_data_t (pam_get_authtok_data_t *data) {
    free(data);
}

static void *pam_get_authtok_thread(void *d) {
    pam_get_authtok_data_t *data = (pam_get_authtok_data_t *) d;
    const char *authtok;
    int res = pam_get_authtok(data->pamh, data->item, &authtok, data->prompt);
    data->callback(res, authtok, data->callback_data);
    pthread_exit(NULL);
    free_pam_get_authtok_data_t(data);
}

void pam_get_authtok_cancel(pam_handle_t *pamh, void *d) {
    // pam_syslog(pamh, LOG_DEBUG, "cancel get_authtok: %p", d);
    pam_get_authtok_data_t *data = (pam_get_authtok_data_t *) d;
    pthread_cancel(data->thread);
    pthread_join(data->thread, NULL);
    free_pam_get_authtok_data_t(data);
}

void *pam_get_authtok_async(pam_handle_t *pamh, int item, const char *prompt, pam_get_authtok_cb callback, const void *callback_data) {
    pam_get_authtok_data_t *data = malloc(sizeof(pam_get_authtok_data_t));
    data->pamh = pamh;
    data->item = item;
    data->callback = callback;
    data->prompt = prompt;
    data->callback_data = callback_data;
    
    pthread_create(&data->thread, NULL, pam_get_authtok_thread, data);
    // pam_syslog(pamh, LOG_DEBUG, "start get_authtok: %p", data);
    return data;
}