//! `modsecurity-axum-example [RULES_FILE] [ADDRESS]`: serves an echo
//! application behind ModSecurity (default: a few inline rules, on
//! 127.0.0.1:8080).

use modsecurity::RulesSet;

/// Used without a rules file: block `<script>` in arguments.
const DEFAULT_RULES: &str = r#"
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@contains <script>" "id:1,phase:2,deny,status:403,log,msg:'XSS attempt'"
"#;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let mut rules = RulesSet::new();
    match args.next() {
        Some(file) => rules.load_from_uri(&file)?,
        None => rules.load(DEFAULT_RULES)?,
    };
    let address = args.next().unwrap_or_else(|| "127.0.0.1:8080".to_string());
    let listener = tokio::net::TcpListener::bind(&address).await?;
    println!("listening on http://{}", listener.local_addr()?);
    modsecurity_axum_example::serve(listener, modsecurity_axum_example::app(rules)).await?;
    Ok(())
}
