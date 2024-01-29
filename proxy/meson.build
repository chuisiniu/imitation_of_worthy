proxy_libs = []
proxy_include = global_inc

ssl_lib_dir = get_option('openssl_lib_path')
if ssl_lib_dir == ''
    ssl_lib = dependency('openssl', main: true, required: false)
    proxy_libs = [ssl_lib]
else
    ssl_header_dir = get_option('openssl_header_path')
    ssl_lib = c_compiler.find_library(
        'ssl',
        dirs: ssl_lib_dir,
        header_include_directories: include_directories(ssl_header_dir))
    crypto_lib = c_compiler.find_library(
        'crypto',
        dirs: ssl_lib_dir,
        header_include_directories: include_directories(ssl_header_dir))
    proxy_include = [include_directories(ssl_header_dir), proxy_include]
    proxy_libs = [ssl_lib, crypto_lib]
endif


executable('proxy',
           files('proxy.c',
                 'proxy_ssl.c',
                 'proxy_qat.c'),
           c_args: '-Wno-deprecated-declarations',
           include_directories: proxy_include,
           link_with: [basic_lib, event_lib],
           dependencies: proxy_libs)
