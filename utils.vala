public async void nap(uint interval, int priority = GLib.Priority.DEFAULT) {
    GLib.Timeout.add(interval, () => {
        nap.callback();
        return false;
    }, priority);
    yield;
}
