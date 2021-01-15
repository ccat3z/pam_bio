using Pam;

public AuthenticateResult do_authenticate(
    PamHandler pamh, AuthenticateFlags flags,
    [CCode(array_length_pos = 2, array_length_cname = "argc")]
    string[] argv
) {
    return AuthenticateResult.SUCCESS;
}