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
"Fsta", " [func]", "add function to FIRST",
"Fstaa", "", "add all functions to FIRST",
"Fstaac", " [comment]", "add all functions to FIRST with a comment",
"Fstd", " [addr]", "delete annotation from FIRST",
"Fstdd", " [id]", "delete annotation from FIRST of a function that don't exist in this file (you can see all created annotations using Fstgc)",
"Fstg", "", "get annotations saved in FIRST",
"Fstgc", "", "get all created annotations saved in FIRST (this does not depend on the opened file)",
"Fsth", " [addr]", "get annotation history of a function",
"Fsthh", " [addr]", "get annotation history of a function that don't exist in this file (you can see all created annotations using Fstgc)",
"Fst+", " [id]", "apply annotations",
"Fsts", " [func]", "scan for similar functions in FIRST",
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
                eprintf("Adding %d functions to FIRST\n", fcns->length);
                if (input[2] == 'c' && input[3] == ' ' && input[4] != '\0' ){
                    do_add_all(core,fcns, input + 4 );
                    break;
                }
                do_add_all(core,fcns,NULL);

            }
            else{
                eprintf("Cant find functions\n");

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
        switch (input[1]){
            case ' ':
            {
                int addr = (int)r_num_math(core->num, input + 2);
                do_delete(core, addr );
                break;
            }
            case 'd':
                if(input[2] == ' '){
                    do_delete_id(input +3 );
                    break;
                }
            default:
                r_core_cmd_help(core,help_msg_Fst);
            
        }
        break;
    case 's':

        switch(input[1]){
        case 'a':
        {
            RList* fcns = core->anal->fcns;
            if(fcns){
                eprintf("Scanning all %d functions in FIRST (Use the ID to apply the annotations using Fst+)\n", fcns->length);
                do_scan_all(core,fcns);
            }
            else
                eprintf("Cant find functions\n");

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

            eprintf("Scanning for similar functions of %s of address 0x%08x\n",fcn->name, fcn->addr);
            do_scan(core, fcn);
            break;
        }
        default:
            r_core_cmd_help(core,help_msg_Fst);
        }
        break;
    case '+':
    {

        RAnalFunction* fcn;
        if (input[1] == ' '){
            char addresss[11];
            strncpy(addresss, input + 2, 10);

            ut64 addr = r_num_math(core->num,addresss);
            if (core->num->nc.errors){
                eprintf("Unknown function address\n");
                break;
            }
            fcn = r_anal_get_fcn_at(core->anal, (ut64)r_num_math(core->num, input + 2),0);
            if(!fcn){
                eprintf("Cant find function\n");
                break;
            }
            int i=2;
            while(input[i] != ' '){
                i++;
                if (i > 15){
                    r_core_cmd_help(core,help_msg_Fst);
                    break;
                }
            }
            while(input[i] == ' ')
                i++;
            do_apply(core, input+i, addr);

        }
        break;
    }    
    // case 'r':
        // read_db();
        break;
    case 'g':
        switch(input[1]){
            case 'c':
                do_created();
                break;
            case '\0':
                do_get();
                break;
            default:
                r_core_cmd_help(core,help_msg_Fst);
        }
        break;
    case 'h':
        switch (input[1]){
            case ' ':
            {
                int addr = (int)r_num_math(core->num, input + 2);
                do_history(addr );
                break;
            }
            case 'h':
                if(input[2] == ' '){
                    do_history_id(input +3 );
                    break;
                }
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
    if(!init_fst)
        if(f_set_config()){
            set_hashes(core);
            init_fst = true;
        }
        
    // if (!init_fcn)
    //     if(populate_fcn(core))
    //         init_fcn = true;
    if (init_fst)
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


