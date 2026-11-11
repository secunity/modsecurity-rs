/* Differential harness: drives libmodsecurity through its C API only.
 * Built twice: against the C++ libmodsecurity.so and against the Rust
 * cdylib. Usage: harness <rules.conf> <requests.txt> */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

static void log_cb(void *data, const void *msg) {
    printf("  LOG %s\n", (const char *)msg);
}

static void report(Transaction *t, const char *stage) {
    ModSecurityIntervention it;
    memset(&it, 0, sizeof(it));
    it.status = 200;
    if (msc_intervention(t, &it)) {
        printf("  INTERVENTION@%s status=%d url=%s log=%s\n", stage, it.status,
               it.url ? it.url : "-", it.log ? it.log : "-");
    }
    msc_intervention_cleanup(&it);
}

static char *read_file(const char *p, size_t *len) {
    FILE *f = fopen(p, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *b = malloc(n + 1); if (fread(b, 1, n, f) != (size_t)n) { n = 0; } b[n] = 0; fclose(f);
    *len = n; return b;
}

int main(int argc, char **argv) {
    ModSecurity *ms = msc_init();
    msc_set_connector_info(ms, "diff-harness");
    msc_set_log_cb(ms, log_cb);
    RulesSet *rules = msc_create_rules_set();
    const char *err = NULL;
    int n = msc_rules_add_file(rules, argv[1], &err);
    printf("RULES %d %s\n", n, err ? err : "");
    if (n < 0) return 1;

    size_t len; char *all = read_file(argv[2], &len);
    /* requests separated by lines "###"; first line "METHOD URI VERSION",
       then headers, a blank line, then the body (verbatim). */
    char *cur = all; int idx = 0;
    while (cur && *cur) {
        char *next = strstr(cur, "\n###\n");
        if (next) { *next = 0; next += 5; }
        if (strncmp(cur, "###\n", 4) == 0) cur += 4;
        if (!*cur) { cur = next; continue; }
        char id[32]; snprintf(id, sizeof(id), "tx-%03d", ++idx);
        Transaction *t = msc_new_transaction_with_id(ms, rules, id, NULL);
        char *line_end = strchr(cur, '\n'); if (line_end) *line_end = 0;
        char method[32], uri[8192], ver[16];
        sscanf(cur, "%31s %8191s %15s", method, uri, ver);
        printf("REQ %s %s %s\n", id, method, uri);
        msc_process_connection(t, "10.0.0.7", 51234, "10.0.0.1", 80);
        report(t, "conn");
        msc_process_uri(t, uri, method, ver);
        report(t, "uri");
        char *p = line_end ? line_end + 1 : NULL;
        while (p && *p && *p != '\n') {
            char *e = strchr(p, '\n'); if (e) *e = 0;
            char *colon = strchr(p, ':');
            if (colon) { *colon = 0; char *v = colon + 1; while (*v == ' ') v++;
                msc_add_request_header(t, (unsigned char *)p, (unsigned char *)v); }
            p = e ? e + 1 : NULL;
        }
        msc_process_request_headers(t);
        report(t, "reqhdr");
        if (p && *p == '\n') { p++; msc_append_request_body(t, (unsigned char *)p, strlen(p)); }
        msc_process_request_body(t);
        report(t, "reqbody");
        msc_add_response_header(t, (unsigned char *)"Content-Type", (unsigned char *)"text/html");
        msc_process_response_headers(t, 200, "HTTP 1.1");
        report(t, "resphdr");
        const char *rb = "<html><body>hello world</body></html>";
        msc_append_response_body(t, (unsigned char *)rb, strlen(rb));
        msc_process_response_body(t);
        report(t, "respbody");
        msc_process_logging(t);
        int64_t ids[512]; size_t k = msc_get_rules_messages_rule_ids(t, ids, 512);
        printf("  RULES_MATCHED");
        for (size_t i = 0; i < k; i++) printf(" %lld", (long long)ids[i]);
        printf("\n");
        msc_transaction_cleanup(t);
        cur = next;
    }
    msc_rules_cleanup(rules);
    msc_cleanup(ms);
    free(all);
    return 0;
}
