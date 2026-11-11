/*
 * C-API benchmark for libmodsecurity: the same program is linked against the
 * C++ library and against the Rust port, so both run identical work.
 *
 *   bench_capi <rules.conf> upstream <iterations>
 *       the request of the C++ project's test/benchmark/benchmark.cc
 *   bench_capi <rules.conf> corpus <iterations> <requests.txt>
 *       each request of a corpus (format of test/differential) per iteration
 *
 * Prints rule load time, transactions/s, per-transaction latency
 * percentiles and the peak RSS.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sys/resource.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>
#include <modsecurity/intervention.h>

static double now(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void drain(Transaction *t) {
    ModSecurityIntervention it; memset(&it, 0, sizeof(it)); it.status = 200;
    msc_intervention(t, &it);
    msc_intervention_cleanup(&it);
}

/* --- test/benchmark/benchmark.cc request ------------------------------- */
static const char *response_body =
    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\r"
    "<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" "
    "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
    "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n\r"
    "  <soap:Body>\n\r"
    "  <EnlightenResponse xmlns=\"http://clearforest.com/\">\n\r"
    "  <EnlightenResult>string</EnlightenResult>\n\r"
    "  </EnlightenResponse>\n\r"
    "  </soap:Body>\n\r"
    "</soap:Envelope>\n\r";

static void upstream_tx(ModSecurity *ms, RulesSet *rules) {
    static const char *h[][2] = {
        {"Host", "net.tutsplus.com"},
        {"User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) "
                       "Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)"},
        {"Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        {"Accept-Language", "en-us,en;q=0.5"},
        {"Accept-Encoding", "gzip,deflate"},
        {"Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7"},
        {"Keep-Alive", "300"},
        {"Connection", "keep-alive"},
        {"Cookie", "PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120"},
        {"Pragma", "no-cache"},
        {"Cache-Control", "no-cache"},
    };
    Transaction *t = msc_new_transaction(ms, rules, NULL);
    msc_process_connection(t, "200.249.12.31", 12345, "127.0.0.1", 80); drain(t);
    msc_process_uri(t, "/test.pl?param1=test&para2=test2", "GET", "1.1"); drain(t);
    for (size_t i = 0; i < sizeof(h) / sizeof(h[0]); i++)
        msc_add_request_header(t, (const unsigned char *)h[i][0], (const unsigned char *)h[i][1]);
    msc_process_request_headers(t); drain(t);
    msc_process_request_body(t); drain(t);
    msc_add_response_header(t, (const unsigned char *)"HTTP/1.1", (const unsigned char *)"200 OK");
    msc_add_response_header(t, (const unsigned char *)"Content-Type", (const unsigned char *)"text/xml; charset=utf-8");
    msc_add_response_header(t, (const unsigned char *)"Content-Length", (const unsigned char *)"200");
    msc_process_response_headers(t, 200, "HTTP 1.2"); drain(t);
    msc_append_response_body(t, (const unsigned char *)response_body, strlen(response_body));
    msc_process_response_body(t); drain(t);
    msc_process_logging(t);
    msc_transaction_cleanup(t);
}

/* --- corpus requests --------------------------------------------------- */
typedef struct { char *method, *uri, *ver; char **hk, **hv; int nh; char *body; size_t blen; } req_t;

static int parse_corpus(const char *path, req_t **out) {
    FILE *f = fopen(path, "rb"); if (!f) return -1;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    char *all = malloc(n + 1); if (fread(all, 1, n, f) != (size_t)n) n = 0; all[n] = 0; fclose(f);
    req_t *reqs = NULL; int count = 0;
    char *cur = all;
    while (cur && *cur) {
        char *next = strstr(cur, "\n###\n");
        if (next) { *next = 0; next += 5; }
        if (strncmp(cur, "###\n", 4) == 0) cur += 4;
        if (!*cur) { cur = next; continue; }
        req_t r; memset(&r, 0, sizeof(r));
        char *le = strchr(cur, '\n'); if (le) *le = 0;
        r.method = malloc(32); r.uri = malloc(8192); r.ver = malloc(16);
        sscanf(cur, "%31s %8191s %15s", r.method, r.uri, r.ver);
        char *p = le ? le + 1 : NULL;
        r.hk = malloc(sizeof(char *) * 64); r.hv = malloc(sizeof(char *) * 64);
        while (p && *p && *p != '\n' && r.nh < 64) {
            char *e = strchr(p, '\n'); if (e) *e = 0;
            char *c = strchr(p, ':');
            if (c) { *c = 0; char *v = c + 1; while (*v == ' ') v++; r.hk[r.nh] = p; r.hv[r.nh] = v; r.nh++; }
            p = e ? e + 1 : NULL;
        }
        if (p && *p == '\n') { r.body = p + 1; r.blen = strlen(p + 1); }
        reqs = realloc(reqs, sizeof(req_t) * (count + 1)); reqs[count++] = r;
        cur = next;
    }
    *out = reqs; return count;
}

static void corpus_tx(ModSecurity *ms, RulesSet *rules, req_t *r) {
    Transaction *t = msc_new_transaction(ms, rules, NULL);
    msc_process_connection(t, "10.0.0.7", 51234, "10.0.0.1", 80); drain(t);
    msc_process_uri(t, r->uri, r->method, r->ver); drain(t);
    for (int i = 0; i < r->nh; i++)
        msc_add_request_header(t, (const unsigned char *)r->hk[i], (const unsigned char *)r->hv[i]);
    msc_process_request_headers(t); drain(t);
    if (r->blen) msc_append_request_body(t, (const unsigned char *)r->body, r->blen);
    msc_process_request_body(t); drain(t);
    msc_add_response_header(t, (const unsigned char *)"Content-Type", (const unsigned char *)"text/html");
    msc_process_response_headers(t, 200, "HTTP 1.1"); drain(t);
    const char *rb = "<html><body>hello world</body></html>";
    msc_append_response_body(t, (const unsigned char *)rb, strlen(rb));
    msc_process_response_body(t); drain(t);
    msc_process_logging(t);
    msc_transaction_cleanup(t);
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b; return (x > y) - (x < y);
}

static void silent(void *d, const void *m) { (void)d; (void)m; }

int main(int argc, char **argv) {
    if (argc < 4) { fprintf(stderr, "usage: %s rules.conf upstream|corpus iterations [corpus]\n", argv[0]); return 2; }
    int corpus = strcmp(argv[2], "corpus") == 0;
    long iters = atol(argv[3]);
    req_t *reqs = NULL; int nreq = 1;
    if (corpus && (nreq = parse_corpus(argv[4], &reqs)) <= 0) { fprintf(stderr, "bad corpus\n"); return 2; }

    ModSecurity *ms = msc_init();
    msc_set_connector_info(ms, "ModSecurity-benchmark v0.0.1-alpha (ModSecurity benchmark utility)");
    msc_set_log_cb(ms, silent);
    RulesSet *rules = msc_create_rules_set();
    const char *err = NULL;
    double t0 = now();
    int n = msc_rules_add_file(rules, argv[1], &err);
    double load = now() - t0;
    if (n < 0) { fprintf(stderr, "rules: %s\n", err); return 1; }

    /* warm-up pass */
    for (int i = 0; i < nreq; i++) corpus ? corpus_tx(ms, rules, &reqs[i]) : upstream_tx(ms, rules);

    long total = iters * nreq;
    double *lat = malloc(sizeof(double) * total);
    long k = 0;
    double start = now();
    for (long it = 0; it < iters; it++)
        for (int i = 0; i < nreq; i++) {
            double a = now();
            corpus ? corpus_tx(ms, rules, &reqs[i]) : upstream_tx(ms, rules);
            lat[k++] = now() - a;
        }
    double elapsed = now() - start;
    qsort(lat, total, sizeof(double), cmp);
    double sum = 0; for (long i = 0; i < total; i++) sum += lat[i];
    struct rusage ru; getrusage(RUSAGE_SELF, &ru);
    printf("rules=%d load_ms=%.1f tx=%ld elapsed_s=%.3f tx_per_s=%.1f mean_us=%.1f p50_us=%.1f p90_us=%.1f p99_us=%.1f max_us=%.1f maxrss_mb=%.1f\n",
           n, load * 1e3, total, elapsed, total / elapsed, sum / total * 1e6,
           lat[total / 2] * 1e6, lat[(long)(total * 0.9)] * 1e6, lat[(long)(total * 0.99)] * 1e6,
           lat[total - 1] * 1e6, ru.ru_maxrss / 1024.0);
    msc_rules_cleanup(rules);
    msc_cleanup(ms);
    return 0;
}
