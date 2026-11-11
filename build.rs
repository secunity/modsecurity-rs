//! Re-emits the nginx build facts discovered by `nginx-sys` (feature flags
//! such as `http_v2`/`http_gzip`) so the code can use
//! `#[cfg(ngx_feature = "...")]` like the C code uses `#if (NGX_HTTP_V2)`.

fn main() {
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES_CHECK");
    println!(
        "cargo::rustc-check-cfg=cfg(ngx_feature, values({}))",
        std::env::var("DEP_NGINX_FEATURES_CHECK").unwrap_or_else(|_| "any()".to_string())
    );
    println!("cargo::rerun-if-env-changed=DEP_NGINX_FEATURES");
    if let Ok(features) = std::env::var("DEP_NGINX_FEATURES") {
        for feature in features.split(',').map(str::trim) {
            println!("cargo::rustc-cfg=ngx_feature=\"{feature}\"");
        }
    }
}
