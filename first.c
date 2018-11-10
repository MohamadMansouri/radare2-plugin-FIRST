#include <stdbool.h>
#include <r_core.h>
#include <r_socket.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "utils.h"

#define SETDESC(x, y) r_config_node_desc (x, y)
#define SETPREF(x, y, z) SETDESC (r_config_set (core->config, x, y), z)








int cmd(void *user, const char *input) {
    // RCmd *rcmd = (RCmd*) user;
    RCore *core = (RCore *) user;
    if (strncmp ("Fst", input, 3)) {
        return false;
    }
    
    set_hashes(core);


    // printf("%s\n", r_core_cmd_str (core, "ph md5"));

    // s_test_connection();
    // history("123456789012345678901234");
    // SETPREF ("http.log", "false", "Show HTTP requests processed");

    printf("%d\n", s_test_connection());
    return true;
}

int init(void *user, const char *_input) { 
    RCmd *rcmd = (RCmd*) user;
    RCore *core = (RCore *) rcmd->data;
    RCoreAutocomplete *Fst = r_core_autocomplete_add (core->autocomplete, "Fst", R_CORE_AUTOCMPLT_DFLT, true);
    r_core_autocomplete_add (Fst, "--version", R_CORE_AUTOCMPLT_OPTN, true);
    
    set_token();
    

    return true; };

RCorePlugin r_core_plugin_test = {.name = "First",
                                  .desc = "r2 plugin for FIRST",
                                  .license = "",
                                  .call = cmd,
                                  .init = init};

#ifndef CORELIB
RLibStruct radare_plugin = {.type = R_LIB_TYPE_CORE,
                            .data = &r_core_plugin_test,
                            .version = R2_VERSION};
#endif
