/* W34 host unit test for src/netifd_status.inc.
 *
 *   cc -I native/src -o /tmp/test_netifd_status tests/test_netifd_status.c
 *   /tmp/test_netifd_status
 *
 * The parser is the only place where the ownership model trusts netifd, so it
 * is kept OS-free and tested on the host with realistic ubus payloads.
 */
#include <stdio.h>
#include <string.h>
#include "netifd_status.inc"

static int failures;

static void check(int cond, const char *what)
{
    if (!cond) {
        printf("FAIL: %s\n", what);
        failures++;
    } else {
        printf("ok: %s\n", what);
    }
}

static void test_empty(void)
{
    struct nd_status st;
    check(nd_parse("{}", &st) == 0, "empty object parses");
    check(st.ok == 1 && st.n == 0 && !st.pending, "empty object has no ifaces");
}

static void test_legacy(void)
{
    static const char *json =
        "{\n"
        " \"radio0\": {\n"
        "  \"up\": true, \"pending\": false,\n"
        "  \"config\": {\"path\": \"pci0000:00/0000:00:00.0\", \"band\": \"2g\"},\n"
        "  \"interfaces\": [\n"
        "   {\"section\": \"default_radio0\", \"ifname\": \"phy0-ap0\",\n"
        "    \"config\": {\"mode\": \"ap\", \"ssid\": \"legacy\",\n"
        "               \"network\": [\"lan\"]},\n"
        "    \"vlans\": [], \"stations\": []},\n"
        "   {\"section\": \"guest\", \"ifname\": \"phy0-ap1\",\n"
        "    \"config\": {\"ifname\": \"phy0-ap1\", \"mode\": \"ap\"},\n"
        "    \"vlans\": [{\"section\": \"guest_vlan10\", \"ifname\": \"phy0-ap1.10\"}],\n"
        "    \"stations\": []}\n"
        "  ]\n"
        " },\n"
        " \"radio1\": {\n"
        "  \"up\": true, \"pending\": false,\n"
        "  \"interfaces\": [{\"section\": \"w5\", \"ifname\": \"wlan1\",\n"
        "                    \"vlans\": []}]\n"
        " }\n"
        "}\n";
    struct nd_status st;
    char sec[ND_SECTION_MAX];

    check(nd_parse(json, &st) == 0 && st.ok && !st.pending, "legacy JSON parses");
    check(st.n == 4, "legacy JSON finds 4 netdev names (incl. AP_VLAN)");
    check(nd_find(&st, "phy0-ap0", sec, sizeof(sec)) &&
          !strcmp(sec, "default_radio0"), "phy0-ap0 section");
    check(nd_find(&st, "phy0-ap1", NULL, 0), "phy0-ap1 found");
    check(nd_find(&st, "phy0-ap1.10", sec, sizeof(sec)) &&
          !strcmp(sec, "guest_vlan10"), "AP_VLAN ifname/section");
    check(nd_find(&st, "wlan1", NULL, 0), "radio master ifname found");
    check(!nd_find(&st, "phy0-ap2", NULL, 0), "absent name not found");
}

static void test_pending(void)
{
    struct nd_status st;
    check(nd_parse("{\"radio0\":{\"up\":false,\"pending\":true,"
                   "\"interfaces\":[]}}", &st) == 0, "pending JSON parses");
    check(st.pending == 1, "pending=true detected");

    check(nd_parse("{\"radio0\":{\"pending\":false,\"up\":true}}", &st) == 0,
          "pending=false JSON parses");
    check(st.pending == 0 && st.up == 1, "pending=false / up=true");
}

static void test_bad(void)
{
    struct nd_status st;
    check(nd_parse("Command failed: Not found", &st) != 0,
          "ubus error text rejected");
    check(nd_parse("", &st) != 0, "empty input rejected");
    check(nd_parse(NULL, &st) != 0, "NULL rejected");
}

static void test_names(void)
{
    struct nd_status st;
    /* No spaces, duplicated names, and a key that merely ends in "ifname".
     * The scanner must only accept "ifname" and must not create duplicates. */
    check(nd_parse("{\"a\":{\"ifname\":\"dup\",\"xifname\":\"evil\"},"
                   "\"b\":{\"ifname\":\"dup\"}}", &st) == 0, "dup JSON parses");
    check(st.n == 1, "duplicate ifname collapsed to one row");
    check(!nd_find(&st, "evil", NULL, 0), "xifname not mistaken for ifname");

    check(nd_parse("{\"b\":{\"ifname\":\"bad name\"}}", &st) == 0,
          "quoted invalid name parses");
    check(st.n == 0, "name with a space rejected");
}

int main(void)
{
    test_empty();
    test_legacy();
    test_pending();
    test_bad();
    test_names();
    if (failures) {
        printf("%d FAILURE(S)\n", failures);
        return 1;
    }
    printf("all netifd_status tests passed\n");
    return 0;
}
