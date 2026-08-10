#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rule_added = 0;
int rule_deleted = 0;

int run_quiet(const char *const argv[]) {
    if (!argv || !argv[0]) return -1;
    if (strcmp(argv[0], "ip") == 0 && strcmp(argv[2], "rule") == 0) {
        if (strcmp(argv[3], "add") == 0) rule_added++;
        if (strcmp(argv[3], "del") == 0) rule_deleted++;
    }
    return 0;
}

#include "../src/spec.h"

/* Mock globals */
size_t g_out_n = 0;
struct output g_out[MAX_OUTPUTS];
const char *g_state_dir = "/tmp";
void load_spec(const char *path) {}
void registry_assign(void) {}

#include "../src/failover.c"

int main(void) {
    /* Test sig_cleanup/cleanup_probe_rule indirectly by checking rule_deleted */
    cleanup_probe_rule();
    if (rule_deleted != 1) {
        fprintf(stderr, "FAIL: cleanup_probe_rule did not run ip rule del\n");
        return 1;
    }
    
    printf("OK\n");
    return 0;
}
