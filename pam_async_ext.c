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
    free_pam_get_authtok_data_t(data);
    pthread_exit(NULL);
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
   sleep(1);

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
   sleep(1);

   ioctl(fd, UI_DEV_DESTROY);
   close(fd);

   return 0;
}

void pam_get_authtok_cancel(pam_handle_t *pamh, void *d) {
    // pam_syslog(pamh, LOG_DEBUG, "cancel get_authtok: %p", d);
    pam_get_authtok_data_t *data = (pam_get_authtok_data_t *) d;
    pthread_t thread = data->thread;
    simulate_enter_password();
    pthread_join(thread, NULL);
}
#elif defined(CANCEL_PAM_CONV_USE_CANCEL_THREAD)
void pam_get_authtok_cancel(pam_handle_t *pamh, void *d) {
    // pam_syslog(pamh, LOG_DEBUG, "cancel get_authtok: %p", d);
    pam_get_authtok_data_t *data = (pam_get_authtok_data_t *) d;
    pthread_cancel(data->thread);
    pthread_join(data->thread, NULL);
    free_pam_get_authtok_data_t(data);
}
#else
#error "unsupport cancel_pam_conv_method"
#endif