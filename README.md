# pam_bio

PAM module that run howdy, fprint and retrieve password in parallel.

# TODO

- [ ] Document
- [ ] disable_{fprint,howdy} by service name
- [ ] Retrieve username before starting authn task

# Usage

```
cat <<EOF > /etc/pam.d/test-pam-bio
#%PAM-1.0

auth [success=1 default=ignore] pam_bio.so debug
auth required pam_unix.so use_first_pass nullok
auth optional pam_permit.so
EOF
```

# Inspired by

- [boltgolt/howdy#484](https://github.com/boltgolt/howdy/pull/484)
- [zsxsoft/libfprint-fprintd](https://github.com/zsxsoft/libfprint-fprintd)