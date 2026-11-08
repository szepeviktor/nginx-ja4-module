# nginx JA4 dynamic module

This HTTP module exports `$ja4` and `$ja4_raw` for incoming TLS connections,
using the shared parser in `ja4.c`. No nginx patch is required.

CI builds and tests modules against Debian 12 and 13 nginx packages.
Debian 11 is excluded because it does not provide the `nginx-dev` package
used by this build.

## Build and install on Debian

For nginx installed from Debian's repositories, use the matching `nginx-dev`
package. Run package installation and the installation/configuration steps below
as root; compile as an ordinary user.

```sh
apt-get update
apt-get install --no-install-recommends nginx nginx-dev build-essential \
    libssl-dev libpcre2-dev zlib1g-dev binutils
```

`nginx-dev` supplies the nginx headers and build scripts under
`/usr/share/nginx/src`. OpenSSL, PCRE2 and zlib development packages satisfy the
configure checks. See the [Debian nginx-dev package](https://packages.debian.org/bookworm/nginx-dev).

Check that the installed nginx and development package versions match:

```sh
dpkg-query -W -f='${Package} ${Version}\n' nginx nginx-dev
/usr/sbin/nginx -V
```

Use packages from the same Debian release and repository. If nginx comes from
nginx.org or a custom build, use its matching source and build options instead
of Debian's `nginx-dev` (see the source-build instructions below).

From this repository's root, copy the build tree into a writable directory and
build only the dynamic module:

```sh
JA4_MODULE_DIR="$(pwd)"
NGINX_BUILD_DIR="$(mktemp -d /tmp/nginx-ja4-build.XXXXXX)"
cp -a /usr/share/nginx/src/. "$NGINX_BUILD_DIR/"
cd "$NGINX_BUILD_DIR"
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module="$JA4_MODULE_DIR"
make modules
```

Keep the repository in place during compilation: the module also builds
`ja4.c` and includes `ja4.h`. The output is
`$NGINX_BUILD_DIR/objs/ngx_http_ja4_module.so`; this does not rebuild or replace
the installed nginx executable.

Install the locally built module under `/usr/local/` to keep it separate from
Debian-managed package files. As root, install the resulting file (replace the build directory below with
the actual path printed by `echo "$NGINX_BUILD_DIR"` in the build shell):

```sh
install -d -m 755 /usr/local/lib/nginx/modules
install -m 755 /tmp/nginx-ja4-build.XXXXXX/objs/ngx_http_ja4_module.so \
    /usr/local/lib/nginx/modules/ngx_http_ja4_module.so
strip --strip-unneeded /usr/local/lib/nginx/modules/ngx_http_ja4_module.so
```

Create `/etc/nginx/modules-enabled/50-mod-http-ja4.conf` as root:

```nginx
load_module /usr/local/lib/nginx/modules/ngx_http_ja4_module.so;
```

Debian's default `/etc/nginx/nginx.conf` includes `modules-enabled/*.conf` in
the main context. For a custom configuration, add that include or the
`load_module` directive directly, exactly once. Then validate and reload as root:

```sh
nginx -t
systemctl reload nginx
```

Run the reload only if the configuration check succeeds. If nginx is not
running yet, use `systemctl start nginx`. Rebuild the module after nginx version
changes. A `module is not binary compatible` or module version error means the
source/build configuration does not match the installed executable; rebuild
against the matching package/source and verify again with `nginx -t`.

## Build against other nginx sources

Use the nginx source version matching the target nginx binary and its build
options (`nginx -V`). You need a C toolchain and OpenSSL development headers.
Run from that nginx source directory, replacing the module path:

```sh
./configure --with-compat --with-http_ssl_module \
    --add-dynamic-module=/absolute/path/to/nginx-ja4-module
make modules
```

The output is `objs/ngx_http_ja4_module.so`. Install it in your nginx modules
directory. `--with-compat` does not make binaries portable across nginx versions
or arbitrary build configurations. The shared parser sources must remain in this directory when compiling.
See nginx's [build options](https://nginx.org/en/docs/configure.html) for
`--with-compat` and `--add-dynamic-module`.

The optional `build-nginx.sh` contains the original Debian sbuild environment
setup for rebuilding nginx packages. It requires root, installs packages and
creates a builder user; it is separate from the module build above.

## Configuration

Load the module in the main context, before `http`:

```nginx
load_module /usr/local/lib/nginx/modules/ngx_http_ja4_module.so;

events {}
http {
    log_format ja4 '$remote_addr "$request" $status ja4=$ja4 raw=$ja4_raw';
    access_log /var/log/nginx/ja4.log ja4;

    server {
        listen 443 ssl;
        server_name example.com;
        ssl_certificate /path/to/fullchain.pem;
        ssl_certificate_key /path/to/privkey.pem;

        location / {
            proxy_set_header X-JA4 $ja4;
            proxy_set_header X-JA4-Raw $ja4_raw;
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

For FastCGI, use `fastcgi_param JA4 $ja4;` and
`fastcgi_param JA4_RAW $ja4_raw;` alongside your usual parameters.
Validate with `nginx -t` before reloading.

Loading enables capture on all HTTP TLS server contexts. Plain HTTP and failed
parses have missing variables (empty when interpolated, `-` in access logs).
Client headers never supply the values. TLS must terminate at this nginx.

The initial ClientHello is retained across HelloRetryRequest and renegotiation,
and shared by keepalive requests and HTTP/2 streams. State belongs to the OpenSSL
SSL object and is freed with it. SNI, ALPN and certificate callbacks are left
untouched. This module installs an OpenSSL context message callback; another
module installing the same callback can conflict, and unknown callbacks cannot
be chained. HTTP/3/QUIC, DTLS and stream/mail modules are outside its scope.
Target OpenSSL 1.1.1 or 3.x; the tested build uses nginx 1.28.0 and OpenSSL 3.x.

## Tests

Build a test nginx executable with `make` and `--with-http_v2_module` in addition
to the options above. From the repository root:

```sh
python3 tests/test_ja4.py
NGINX_BINARY=/path/to/nginx/objs/nginx \
JA4_MODULE=/path/to/nginx/objs/ngx_http_ja4_module.so \
python3 tests/test_nginx.py
```

Tests run an isolated, unprivileged loopback server with temporary certificates.
They compare exported values with the actual ClientHello for TLS 1.2/1.3,
keepalive, SNI, absent SNI, session resumption and HelloRetryRequest. HTTP/2
tests use the optional Python `h2` package. No system configuration is changed.

Implementation references: [nginx SSL module source](https://github.com/nginx/nginx/blob/release-1.28.0/src/http/modules/ngx_http_ssl_module.c)
and [OpenSSL message callback API](https://docs.openssl.org/3.0/man3/SSL_CTX_set_msg_callback/).
