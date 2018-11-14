#include <stdbool.h>
#include <r_core.h>
#include <r_socket.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "utils.h"

#define SETDESC(x, y) r_config_node_desc (x, y)
#define SETPREF(x, y, z) SETDESC (r_config_set (core->config, x, y), z)


void usage() {
    eprintf ("Usage: pde[ ?ac] <func> plugin for radeco\n");
    eprintf ("| pde <func>   decompile current function\n");
    eprintf ("| pde?         show this help\n");
    eprintf ("| pdea <func>  analyze current function with radeco\n");
    eprintf ("| pdec         send information to radeco\n");
    eprintf ("| pder <cmd>   send <cmd> to radeco directly\n");
    eprintf ("| pdes         respawn radeco subprocess\n");
}


// int cmd_pde(const char *input) {
//     static RSocketProc *radeco_proc = NULL;
//     if (!radeco_proc) {
//         radeco_proc = spawn_radeco();
//         if (!radeco_proc) {
//             eprintf("Spawning radeco process failed\n");
//             return true;
//         }
//     }

//     if (!input) {
//         return true;
//     }
//     const char *query = input + 1;
//     switch (input[0]) {
//     case ' ':
//         proc_sendf (radeco_proc, "decompile %s\n", query);
//         read_radeco_output (radeco_proc);
//         break;
//     case 'a':
//         proc_sendf (radeco_proc, "analyze %s\n", query);
//         read_radeco_output (radeco_proc);
//         break;
//     case 'c':
//         proc_sendf (radeco_proc, "connect http://localhost:%u\n", PORT);
//         read_radeco_output (radeco_proc);
//         break;
//     case 'r':
//         proc_sendf (radeco_proc, "%s\n", query);
//         read_radeco_output (radeco_proc);
//         break;
//     case 's':
//         radeco_proc = spawn_radeco ();
//         if (!radeco_proc) {
//             eprintf ("Spawning radeco process failed\n");
//             return true;
//         }
//         break;
//     case '\0':
//     case '?':
//     default:
//         usage ();
//     }
//     return true;
// }








int cmd(void *user, const char *input) {
    // RCmd *rcmd = (RCmd*) user;
    RCore *core = (RCore *) user;
    if (strncmp ("Fst", input, 3)) {
        return false;
    }
    
    set_hashes(core);
    char *homedir = getenv("HOME");
    printf("%s\n",homedir );
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
    
    f_set_config();

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
