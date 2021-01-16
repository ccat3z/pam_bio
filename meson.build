project(
    'pam_bio', 'vala', 'c',
    version: '0.0.1',
    license: 'GPLv2+',
    meson_version: '>= 0.50.0'
)

vapi_dir = meson.current_source_dir() / 'vapi'
add_project_arguments(['--vapidir', vapi_dir], language: 'vala')

valac = meson.get_compiler('vala')
cc = meson.get_compiler('c')

glib_dep = dependency('glib-2.0')
gobject_dep = dependency('gobject-2.0')
gio_dep = dependency('gio-2.0')
pam_dep = cc.find_library('pam', has_headers: 'security/pam_modules.h')

enable_fprint = get_option('enable_fprint')
howdy_bin_path = get_option('howdy_compare')
enable_howdy = howdy_bin_path != ''

conf = configuration_data()
conf.set_quoted('HOWDY_COMPARE', howdy_bin_path)
conf.set('ENABLE_FPRINT', enable_fprint)
configure_file(output: 'config.h', configuration: conf)

auth = static_library(
    'auth',
    name_prefix: '',
    sources: ['auth.vala', 'utils.vala', 'pam.vala', 'fprint.vala', 'howdy.vala'],
    dependencies: [
        glib_dep,
        gobject_dep,
        gio_dep,
        pam_dep,
        valac.find_library('pam', dirs: vapi_dir),
        valac.find_library('config', dirs: vapi_dir),
        valac.find_library('posix')
    ],
    vala_args: [
        enable_fprint ? ['-D', 'ENABLE_FPRINT'] : [],
        enable_howdy ? ['-D', 'ENABLE_HOWDY'] : [],
    ]
)
auth_dep = declare_dependency(link_with: auth)

pam_bio = shared_module(
    'pam_bio',
    name_prefix: '',
    sources: ['pam_bio.c'],
    dependencies: [
        pam_dep,
        glib_dep,
        auth_dep
    ],
    install: true,
    install_dir: '/lib/security'
)