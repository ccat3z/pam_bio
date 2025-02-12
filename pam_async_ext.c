#include "pam_async_ext.h"
#include "config.h"
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <linux/uinput.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    pam_handle_t *pamh;
    pthread_t thread;
    int item;
    const char *prompt;
    const char *authtok;
    GSource *cancel_source;
} pam_get_authtok_data;

static void free_pam_get_authtok_data (pam_get_authtok_data *data) {
    g_source_unref(data->cancel_source);
    free(data);
}

static gboolean pam_get_authtok_cancel(GCancellable *cancellable, GTask *task);

static void *pam_get_authtok_thread(GTask *task) {
    pam_get_authtok_data *data = g_task_get_task_data(task);
    pam_handle_t *pamh = data->pamh;

    if (g_task_set_return_on_cancel(task, FALSE)) {
        int res = pam_get_authtok(pamh, data->item, &data->authtok, data->prompt);
        g_task_return_int(task, res);
    }

    g_source_destroy(data->cancel_source);
    g_object_unref(task);
    pthread_exit(NULL);
}

void pam_get_authtok_async(
    pam_handle_t *pamh, int item, const char *prompt,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer callback_data
) {
    pam_get_authtok_data *data = malloc(sizeof(pam_get_authtok_data));
    data->item = item;
    data->prompt = prompt;
    data->pamh = pamh;

    GTask *task = g_task_new(NULL, cancellable, callback, callback_data);
    g_task_set_task_data(task, data, (GDestroyNotify) free_pam_get_authtok_data);

    pthread_create(&data->thread, NULL, (void *(*)(void *)) pam_get_authtok_thread, task);

    data->cancel_source = g_cancellable_source_new(cancellable);
    g_source_set_callback(data->cancel_source, G_SOURCE_FUNC(pam_get_authtok_cancel), task, NULL);
    g_source_attach(data->cancel_source, NULL);
}

int pam_get_authtok_finish (
    pam_handle_t *pamh,
    GAsyncResult *result,
    const char **authtok,
    GError **error
) {
    GTask *task = G_TASK(result);
    pam_get_authtok_data *data = g_task_get_task_data(task);
    if (authtok != NULL)
        *authtok = data->authtok;
    
    return g_task_propagate_int(G_TASK(result), error);
}

#ifdef CANCEL_PAM_CONV_USE_SIMULATE_ENTER_KEY
static void uinput_emit(int fd, int type, int code, int val)
{
   struct input_event ie;

   ie.type = type;
   ie.code = code;
   ie.value = val;
   /* timestamp values below are ignored */
   ie.time.tv_sec = 0;
   ie.time.tv_usec = 0;

   write(fd, &ie, sizeof(ie));
}

static void uinput_press(int fd, int code) {
   uinput_emit(fd, EV_KEY, code, 1);
   uinput_emit(fd, EV_SYN, SYN_REPORT, 0);
   uinput_emit(fd, EV_KEY, code, 0);
   uinput_emit(fd, EV_SYN, SYN_REPORT, 0);
}

static int simulate_enter_password() {
   struct uinput_setup usetup;
   int fd = open("/dev/uinput", O_WRONLY | O_NONBLOCK);

   /*
    * The ioctls below will enable the device that is about to be
    * created, to pass key events, in this case the space key.
    */
   ioctl(fd, UI_SET_EVBIT, EV_KEY);
   ioctl(fd, UI_SET_KEYBIT, KEY_A);
   ioctl(fd, UI_SET_KEYBIT, KEY_ENTER);

   memset(&usetup, 0, sizeof(usetup));
   usetup.id.bustype = BUS_USB;
   usetup.id.vendor = 0x1;
   usetup.id.product = 0x1;
   strcpy(usetup.name, "Simulate keyboard");

   ioctl(fd, UI_DEV_SETUP, &usetup);
   ioctl(fd, UI_DEV_CREATE);

   /*
    * On UI_DEV_CREATE the kernel will create the device node for this
    * device. We are inserting a pause here so that userspace has time
    * to detect, initialize the new device, and can start listening to
    * the event, otherwise it will not notice the event we are about
    * to send. This pause is only needed in our example code!
    */
   g_usleep(250000);

   /* Key press, report the event, send key release, and report again */
   uinput_press(fd, KEY_A);
   uinput_press(fd, KEY_A);
   uinput_press(fd, KEY_A);
   uinput_press(fd, KEY_A);
   uinput_press(fd, KEY_A);
   uinput_press(fd, KEY_A);
   uinput_press(fd, KEY_ENTER);

   /*
    * Give userspace some time to read the events before we destroy the
    * device with UI_DEV_DESTOY.
    */
   g_usleep(250000);

   ioctl(fd, UI_DEV_DESTROY);
   close(fd);

   return 0;
}

static gboolean pam_get_authtok_cancel(GCancellable *cancellable, GTask *task) {
    g_object_ref(task);
    pam_get_authtok_data *data = g_task_get_task_data(task);
    pam_handle_t *pamh = data->pamh;
    pthread_t thread = data->thread;

    simulate_enter_password();
    pthread_join(thread, NULL);
    pam_set_item(pamh, PAM_AUTHTOK, NULL);

    g_object_unref(task);
    return G_SOURCE_REMOVE;
}
#elif defined(CANCEL_PAM_CONV_USE_CANCEL_THREAD)
static gboolean pam_get_authtok_cancel(GCancellable *cancellable, GTask *task) {
    g_object_ref(task);
    pam_get_authtok_data *data = g_task_get_task_data(task);
    pthread_cancel(data->thread);
    pthread_join(data->thread, NULL);

    g_object_unref(task);
    return G_SOURCE_REMOVE;
}
#else
#error "unsupport cancel_pam_conv_method"
#endif