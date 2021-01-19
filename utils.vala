class WaitGroup : Object {
    private int finished = 0;

    public void finish_cb() {
        Idle.add(() => {
            finished++;
            if (any_cb != null) {
                any_cb();
            }
            return Source.REMOVE;
        });
    }
    
    public async void wait_n(int n) {
        while (n-- > 0) {
            yield wait_any();
        }
    }

    private SourceFunc? any_cb;
    public async void wait_any() {
        finished--;
        if (finished < 0) {
            any_cb = wait_any.callback;
            yield;
            any_cb = null;
        }
    }
}