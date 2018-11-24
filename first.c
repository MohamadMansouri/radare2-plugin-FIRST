#include <stdbool.h>
#include <r_core.h>
#include <r_socket.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "utils.h"

#define SETDESC(x, y) r_config_node_desc (x, y)
#define SETPREF(x, y, z) SETDESC (r_config_set (core->config, x, y), z)




bool init_fst = false;
bool init_fcn = false;

static const char *help_msg_Fst[] = {
"Usage:", "Fst[?asug]", "FIRST plugin",
"Fst", "", "test connection to server",
"Fst?", "", "show this help",
"Fsta", "[func]", "add function to FIRST",
"Fstaa", "", "add all functions to FIRST",
"Fstaac", "[comment]", "add all functions to FIRST with a comment",
"Fstd", "[id]", "delete annotation",
"Fstu", "[id]", "unapply function metadata",
"Fstg", "", "get all annotation saved in FIRST",
"Fstgc", "[id]", "get created function metadata",
"Fstgh", "[id]", "get history function metadata",
"Fsts", "[func]", "scan for similar functions in FIRST",
"Fstsa", "", "scan all functions for similar functions in FIRST",
NULL
};



int cmd_fst(RCore* core, const char *input) {


    if (!input) {
        return true;
    }

    switch (input[0]) {
    case 'a':
        switch(input[1]){
        case 'a':
        {
            RList* fcns = core->anal->fcns;
            if(fcns){
                r_cons_printf("Adding %d functions to FIRST\n", fcns->length);
                if (input[2] == 'c' && input[3] == ' ' && input[4] != '\0' ){
                    do_add_all(core,fcns, input + 4 );
                    break;
                }
                do_add_all(core,fcns,NULL);
                // int pop_s = 0 ;
                // Metadata *pop_fcn = get_fcns_db(&pop_s);
                // for (int i=0; i< pop_s; ++i ){
                //     printf("\n\n\n");
                //     printf("id = \t%s\n", (pop_fcn+i)->id);

                // }
            }
            else{

            }
            break;
        }
        case ' ':
        case '\0':
        {
            RAnalFunction* fcn;
            if (input[1] == ' '){

                fcn = r_anal_fcn_find_name(core->anal, input+2);

                if (!fcn){
                    ut64 addr = r_num_math(core->num, input + 2);
                    if (core->num->nc.errors){
                        eprintf("Unknown function address or name\n");
                        break;
                    }
                    fcn = r_anal_get_fcn_at(core->anal, (ut64)r_num_math(core->num, input + 2),0);
                    if(!fcn){
                        eprintf("Cant find function\n");
                        break;
                    }
                }
            }
            else{
                ut64 addr = r_num_math(core->num, "$FB");
                if (core->num->nc.errors){
                    eprintf("Cant find function\n");
                    break;
                }
                fcn = r_anal_get_fcn_at(core->anal, addr,0);
                if(!fcn){
                    eprintf("Cant find function\n");
                    break;
                }
            }

            eprintf("Adding function %s of address 0x%08x\n",fcn->name, fcn->addr);
            do_add(core, fcn);
            break;
        }
        default:
            r_core_cmd_help(core,help_msg_Fst);
        }
        break;
    case 'd':
        if(input[1] == ' ' && strlen(input+2) == 25)
            do_delete(core, input+2 );
        else
            eprintf("Missing or wrong format id\n");
        break;
    case 's':
        switch(input[1]){
        case 'a':
            eprintf("scan all\n");
            break;
        case '\0':
            eprintf("scan function\n");
            break;
        default:
            r_core_cmd_help(core,help_msg_Fst);
        }
        break;
    case 'u':
        read_db();
        eprintf("unapply metadata\n");
        break;
    case 'g':
        switch(input[1]){
            case 'c':
                eprintf("get created\n");
                break;
            case 'h':
                eprintf("get history\n");
                break;
            case '\0':
                do_get();
                break;
            default:
                r_core_cmd_help(core,help_msg_Fst);
        }
        break;
    case '\0':
        if(s_test_connection())
            eprintf("You are connected to FIRST server...\n");
        else{
            char *homedir = NULL;
            homedir = (char*)malloc(strlen(getenv("HOME"))+ strlen("/root/.config/first/first.config"));
            strcpy(homedir,getenv("HOME"));
            eprintf("Problem connecting to FIRST server... Check the configuration file at %s\n", strcat(homedir,"/.config/first/first.config"));
        }
        break;
    case '?':
    default:
        r_core_cmd_help(core,help_msg_Fst);
    }
    return true;
}








int cmd(void *user, const char *input) {
    RCore *core = (RCore *) user;
    if (strncmp ("Fst", input, 3)) {
        return false;
    }
    if(!init_fst){
        set_hashes(core);
        // if(!initialize_db()){
        //     eprintf("Failed initializing DB!\n");
        //     return true;
        // }
        init_fst = true;
    }
    if (!init_fcn)
        if(populate_fcn(core))
            init_fcn = true;

    // int pop_s = 0 ;
    // Metadata *pop_fcn = get_fcns_db(&pop_s);
    // for (int i=0; i< pop_s; ++i ){
    //     // printf("name = \t%s\n", pop_fcn->name);
    //     printf("orig_name = \t%s\n", (pop_fcn+i)->original_name);
    //     printf("segment = \t%d\n", (pop_fcn+i)->segment);
    //     printf("address = \t%d\n", (pop_fcn+i)->address);
    // }
    cmd_fst(core,input+3);

    return true;
}

int init(void *user, const char *_input) { 
    RCmd *rcmd = (RCmd*) user;
    RCore *core = (RCore *) rcmd->data;
    RCoreAutocomplete *Fst = r_core_autocomplete_add (core->autocomplete, "Fst", R_CORE_AUTOCMPLT_DFLT, true);
    // r_core_autocomplete_add (Fst, "Fsta", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fstaa", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fstap", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fstg", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fstgh", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fstgc", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fsts", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fstsa", R_CORE_AUTOCMPLT_OPTN, true);
    // r_core_autocomplete_add (Fst, "Fstu", R_CORE_AUTOCMPLT_OPTN, true);
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


//05bf1fe4259178b7a7a02f0e7