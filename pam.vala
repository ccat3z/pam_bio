using Pam;

namespace Pam.Conversation {
    [CCode(has_target = false)]
    private delegate int ConvFunc(int num_msg, PamMessage **msg, out PamResponse *resp, void *appdata_ptr);

    public void conv(PamHandler pamh, MessageStyle style, string msg) {
        PamConv *pc; pamh.get_item(ItemType.CONV, out pc);

        PamMessage pm = { style, msg };
        var pm_list = &pm;
        PamResponse *res;

        ConvFunc conv = (ConvFunc) pc->conv;
        conv(1, &pm_list, out res, pc->appdata_ptr);
    }
}