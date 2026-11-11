# ModSecurity-nginx (Rust port)

A Rust port of [ModSecurity-nginx](https://github.com/owasp-modsecurity/ModSecurity-nginx)
v1.0.4, the nginx connector for libmodsecurity. It is built as a dynamic
nginx module on top of the Rust port of libmodsecurity
(`../modsecurity-rust`), which it links in directly, so the module is a
single `.so` with no dependency on `libmodsecurity.so.3`.

The directives, their semantics and the request processing (access phase,
header and body filters, log phase, interventions, configuration merging)
are those of the C module; see [MIGRATION.md](MIGRATION.md) for the mapping
and the differences.

# Compilation

The module is built with [ngx-rust](https://github.com/nginx/ngx-rust)
against a configured nginx source tree (bindgen needs libclang). Configure
nginx with `--with-compat` (and the modules you use), then:

```sh
export NGINX_SOURCE_DIR=/path/to/nginx-1.28.0
export NGINX_BUILD_DIR=/path/to/nginx-1.28.0/objs   # the configured build dir
cargo build --release
cp target/release/libngx_http_modsecurity_module.so /path/to/nginx/modules/ngx_http_modsecurity_module.so
```

and load it in `nginx.conf`:

```nginx
load_module modules/ngx_http_modsecurity_module.so;
```

The module must be loaded by an nginx built from the same source with the
same `./configure` options (nginx checks the module signature).

Cargo features: `sanity-checks` (C `MODSECURITY_SANITY_CHECKS`) and `ddebug`
(C `MODSECURITY_DDEBUG`), both off by default.

# Usage

ModSecurity for nginx extends your nginx configuration directives.
It adds four new directives and they are:

modsecurity
-----------
**syntax:** *modsecurity on | off*

**context:** *http, server, location*

**default:** *off*

Turns on or off ModSecurity functionality.
Note that this configuration directive is no longer related to the SecRule state.
Instead, it now serves solely as an nginx flag to enable or disable the module.

modsecurity_rules_file
----------------------
**syntax:** *modsecurity_rules_file &lt;path to rules file&gt;*

**context:** *http, server, location*

**default:** *no*

Specifies the location of the modsecurity configuration file, e.g.:

```nginx
server {
    modsecurity on;
    location / {
        root /var/www/html;
        modsecurity_rules_file /etc/my_modsecurity_rules.conf;
    }
}
```

modsecurity_rules_remote
------------------------
**syntax:** *modsecurity_rules_remote &lt;key&gt; &lt;URL to rules&gt;*

**context:** *http, server, location*

**default:** *no*

Specifies from where (on the internet) a modsecurity configuration file will be downloaded.
It also specifies the key that will be used to authenticate to that server:

```nginx
server {
    modsecurity on;
    location / {
        root /var/www/html;
        modsecurity_rules_remote my-server-key https://my-own-server/rules/download;
    }
}
```

modsecurity_rules
-----------------
**syntax:** *modsecurity_rules &lt;modsecurity rule&gt;*

**context:** *http, server, location*

**default:** *no*

Allows for the direct inclusion of a ModSecurity rule into the nginx configuration.
The following example is loading rules from a file and injecting specific configurations per directory/alias:

```nginx
server {
    modsecurity on;
    location / {
        root /var/www/html;
        modsecurity_rules_file /etc/my_modsecurity_rules.conf;
    }
    location /ops {
        root /var/www/html/opts;
        modsecurity_rules '
          SecRuleEngine On
          SecDebugLog /tmp/modsec_debug.log
          SecDebugLogLevel 9
          SecRuleRemoveById 10
        ';
    }
}
```

modsecurity_transaction_id
--------------------------
**syntax:** *modsecurity_transaction_id string*

**context:** *http, server, location*

**default:** *no*

Allows to pass transaction ID from nginx instead of generating it in the library.
This can be useful for tracing purposes, e.g. consider this configuration:

```nginx
log_format extended '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent" $request_id';

server {
    server_name host1;
    modsecurity on;
    modsecurity_transaction_id "host1-$request_id";
    access_log logs/host1-access.log extended;
    error_log logs/host1-error.log;
    location / {
        ...
    }
}

server {
    server_name host2;
    modsecurity on;
    modsecurity_transaction_id "host2-$request_id";
    access_log logs/host2-access.log extended;
    error_log logs/host2-error.log;
    location / {
        ...
    }
}
```

Using a combination of log_format and modsecurity_transaction_id you will
be able to find correlations between access log and error log entries
using the same unique identificator.

String can contain variables.

modsecurity_use_error_log
-----------
**syntax:** *modsecurity_use_error_log on | off*

**context:** *http, server, location*

**default:** *on*

Turns on or off ModSecurity error log functionality.

# Testing

* OWASP CRS regression suite through a real nginx:
  `../modsecurity-rust/test/crs/run.sh` with `MODULE_SO` set to the built
  module (see the script header).
* The C module's own nginx-tests (`tests/*.t` of ModSecurity-nginx) run with
  `TEST_NGINX_GLOBALS="load_module /path/to/ngx_http_modsecurity_module.so;"`
  and `TEST_NGINX_BINARY=/path/to/nginx prove modsecurity*.t` from an
  nginx-tests checkout.

# License

Apache License 2.0, like the original project (see `LICENSE`).
