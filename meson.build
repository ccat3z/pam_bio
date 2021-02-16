project(
    'pam_bio', 'vala', 'c',
    version: '0.0.1',
    license: 'GPLv2+',
    meson_version: '>= 0.54.0'
)

# build config
enable_fprint = get_option('enable_fprint')
howdy_bin_path = get_option('howdy_compare')
cancel_pam_conv_method = get_option('cancel_pam_conv_method')
enable_howdy = howdy_bin_path != ''
vapi_dir = meson.current_source_dir() / 'vapi'

# compilers
valac = meson.get_compiler('vala')
cc = meson.get_compiler('c')

# external libraries
glib_dep = dependency('glib-2.0')
gobject_dep = dependency('gobject-2.0')
gio_dep = dependency('gio-2.0')
gee_dep = dependency('gee-0.8')
pam_dep = cc.find_library('pam', has_headers: 'security/pam_modules.h')
pam_vala_dep = valac.find_library('pam', dirs: vapi_dir)
posix_vala_dep = valac.find_library('posix')

# project arguments
add_project_arguments([
    '--vapidir', vapi_dir,
    enable_fprint ? ['-D', 'ENABLE_FPRINT'] : [],
    enable_howdy ? ['-D', 'ENABLE_HOWDY'] : [],
], language: 'vala')
add_project_arguments([
    '-DG_LOG_DOMAIN="PamBio"',
], language: 'c')

# targets

# config.h
conf = configuration_data()
conf.set_quoted('HOWDY_COMPARE', howdy_bin_path)
conf.set('ENABLE_FPRINT', enable_fprint)
conf.set('CANCEL_PAM_CONV_USE_' + cancel_pam_conv_method.to_upper(), true)
configure_file(output: 'config.h', configuration: conf)
config_vala_dep = valac.find_library('config', dirs: vapi_dir)

# pam_biod
pam_bio_daemon = executable(
    'pam_biod',
    sources: [
        'daemon.vala', 'dbus/dbus.vala', 'context.vala', 'config.vala',
        'authn/base.vala',
        'authn/fprint.vala', 'dbus/fprint.vala',
        'authn/howdy.vala',
        'authn/parallel.vala'
    ],
    dependencies: [
        glib_dep,
        gobject_dep,
        gio_dep,
        pam_dep, pam_vala_dep,
        gee_dep,
        posix_vala_dep,
        config_vala_dep
    ],
    install: true
)

# pam_bio.so
pam_bio_vala = static_library(
    'pam_bio_vala',
    sources: [
        'pam_bio.vala', 'context.vala', 'config.vala',
        'authn/base.vala',
        'authn/password.vala',
        'authn/parallel.vala',
        'authn/daemon.vala', 'dbus/daemon.vala'
    ],
    dependencies: [
        glib_dep,
        gobject_dep,
        gio_dep,
        pam_dep, pam_vala_dep,
        gee_dep,
        posix_vala_dep,
        config_vala_dep
    ]
)
pam_bio_vala_dep = declare_dependency(link_with: pam_bio_vala)
pam_bio = shared_module(
    'pam_bio',
    name_prefix: '',
    sources: ['pam_bio.c', 'pam_async_ext.c'],
    dependencies: [
        pam_dep,
        glib_dep,
        pam_bio_vala_dep
    ],
    install: true,
    install_dir: '/lib/security'
)

# data
install_data(
    'data/xyz.ccat3z.pambio.dbus.conf',
    install_dir: '/usr/share/dbus-1/system.d',
    rename: 'xyz.ccat3z.pambio.conf'
)

install_data(
    'data/xyz.ccat3z.pambio.dbus.service',
    install_dir: '/usr/share/dbus-1/system-services',
    rename: 'xyz.ccat3z.pambio.service'
)

custom_target(
    'pam_biod.service',
    command: [
        'sed',
        's#@PAM_BIOD_PATH@#' + (get_option('prefix') / get_option('bindir') / pam_bio_daemon.name()) + '#g',
        '@INPUT@'
    ],
    capture: true,
    input: 'data/pam_biod.service',
    output: 'pam_biod.service',
    install: true,
    install_dir: get_option('libdir') / 'systemd/system'
)