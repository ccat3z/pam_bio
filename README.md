# pam_bio

PAM module that run howdy, fprint and retrieve password in parallel.

# TODO

- [ ] Document
- [ ] disable_{fprint,howdy} by service name
- [ ] Retrieve username before starting authn task
- [ ] Check gdm settings before start fprint authn

# Build

``` sh
meson setup .build
meson compile -C .build
meson install -C .build  # install pam_bio.so to /lib/security
```

# Usage

```
cat <<EOF > /etc/pam.d/test-pam-bio
#%PAM-1.0

auth [success=1 default=ignore] pam_bio.so debug
auth required pam_unix.so use_first_pass nullok
auth optional pam_permit.so
EOF
```

# Options

- `debug`
- `enable_ssh`
- `enable_closed_lid`
- `modules=howdy,fprint,pass`

# Return Values

- `PAM_SUCCESS`: Authenticate succeed.
- `PAM_CRED_INSUFFICIENT`:
  User entered password, but not sure whether the password is correct.
  It should be check by `pam_unix.so use_first_pass`.
- `PAM_AUTHINFO_UNAVAIL`:
  No modules can access authentication information.
  E.g. fprint cannot claim fingerprint device.
- `PAM_AUTH_ERR`: All modules failure and last module return `PAM_AUTH_ERR`.
- `PAM_MAXTRIES`: All modules failure and last module return `PAM_MAXTRIES`.
- `PAM_USER_UNKNOWN`: All modules failure and last module return `PAM_USER_UNKNOWN`.

# Inspired by

- [boltgolt/howdy#484](https://github.com/boltgolt/howdy/pull/484)
- [zsxsoft/libfprint-fprintd](https://github.com/zsxsoft/libfprint-fprintd)