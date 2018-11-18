#include <stdbool.h>
#include <r_core.h>
#include <r_socket.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "utils.h"
#include "jsmn.h"
#include "ini.h"



FS_config f_server_config;

static bool checkedin= false;
binary_info hashes;
const char* path[10] = {"api/test_connection", "api/sample/checkin","api/metadata/add","api/metadata/history","api/metadata/applied","api/metadata/unapplied","api/metadata/delete","api/metadata/created","api/metadata/get","api/metadata/scan"};
CURL *curl;
char* response=NULL;

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}



static
void dump(const char *text,
FILE *stream, unsigned char *ptr, size_t size)
{
  fprintf(stream, "%s, %d bytes\n",text, (long)size, (long)size);
  printf("%s\n", ptr);
  
}
 
static
int debug_response(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  const char *text;
  (void)handle; /* prevent compiler warning */
  (void)userp;
 
  switch (type) {
  case CURLINFO_TEXT:
    return 0;
  default: /* in case a new one is introduced to shock us */
    return 0;
 
  case CURLINFO_HEADER_OUT:
    return 0;
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    return 0;
    break;
  case CURLINFO_HEADER_IN:
    return 0;
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    return 0;
    break;
  }
 
  dump(text, stderr, (unsigned char *)data, size);
  return 0;
}

void dump_created_metadata(char* r, jsmntok_t* t, int j, RespCreated* resp_created){
  for(int i=1;i<=(t->size)*2;i+=2){

    if(!jsoneq(r, t+i, "name") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* name = (char*) malloc(size);
      if (name == NULL)
      strncpy(name,r+(t+i+1)->start,size);
      memset(name+size, '\0',1);
      (resp_created->metadata+j)->name = name;
      continue;
    }
    
    if(!jsoneq(r, t+i, "prototype") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* prototype = (char*) malloc(size);
      strncpy(prototype,r+(t+i+1)->start,size);
      memset(prototype+size, '\0',1);
      (resp_created->metadata+j)->prototype = prototype;
      continue;
    }
    
    if(!jsoneq(r, t+i, "comment") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* comment = (char*) malloc(size);
      strncpy(comment,r+(t+i+1)->start,size);
      memset(comment+size, '\0',1);
      (resp_created->metadata+j)->comment = comment;
      continue;
    }      
    
    if(!jsoneq(r, t+i, "rank") && (t+i+1)->type == JSMN_PRIMITIVE){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* rank = (char*) malloc(size);
      strncpy(rank,r+(t+i+1)->start,size);
      memset(rank+size, '\0',1);
      (resp_created->metadata+j)->rank = atoi(rank);
      continue;
    }     
    
    if(!jsoneq(r, t+i, "id") && (t+i+1)->type == JSMN_PRIMITIVE){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* id = (char*) malloc(size);
      strncpy(id,r+(t+i+1)->start,size);
      memset(id+size, '\0',1);
      (resp_created->metadata+j)->id = id;
      continue;
    }
  }     
}
RespCreated* dump_created(char* r, jsmntok_t* t){
  int i=1;
  if (!jsoneq(r, t+i, "failed") && (t+i+1)->type == JSMN_PRIMITIVE && *(r+(t+i+1)->start) == 'f'){
    i+=2;
    RespCreated* resp_created;
    resp_created = (RespCreated*) malloc(sizeof(RespCreated));
    resp_created->metadata = NULL;
    resp_created->size = 0;
    if (!jsoneq(r, t+i, "pages") && (t+i+1)->type == JSMN_PRIMITIVE ){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* pages = (char*) malloc(size);
      strncpy(pages,r+(t+i+1)->start,size);
      memset(pages+size, '\0',1);
      resp_created->pages= atoi(pages);
      i+=2;
      if (!jsoneq(r, t+i, "results") && (t+i+1)->type == JSMN_ARRAY && (t+i+1)->size){
        resp_created->size = (t+i+1)->size;
        resp_created->metadata = (MetadataServer*) malloc(sizeof(MetadataServer)*resp_created->size);
        for(int j=0;j<resp_created->size;j++){
          jsmntok_t* g = (t+i+j+2);
          dump_created_metadata(r,g,j,resp_created);
          (resp_created->metadata+j)->address=-1;
          (resp_created->metadata+j)->creator=NULL;
          (resp_created->metadata+j)->similarity=0;
        }
      }
      return resp_created;
    }
  }
  return NULL;
}


//server connection

size_t data_callback(void *ptr, size_t size, size_t nmemb, void *stream){
  action act = *(action*)stream;
  long http_code = 0;
  curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code);
  if (http_code == 200)
    response = (char*)ptr;

  return size*nmemb;
}


void send_g(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream))
{
  s_check_in(act);

  curl = curl_easy_init();
  CURLcode res;

  char url[strlen(f_server_config._protocol)+strlen(f_server_config._server)+strlen(path[act])+strlen(token)];
  sprintf(url,"%s://%s/%s/%s",f_server_config._protocol, f_server_config._server, path[act], token);
  if (parms != NULL)
    strcat(url,parms); 

  if(curl) {
    
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION,debug_response);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&act);
    curl_easy_setopt(curl, CURLOPT_PORT, f_server_config._port);

    res = curl_easy_perform(curl);
    
    if(res != CURLE_OK)
    fprintf(stderr, "failed to connect to server: %s\n",curl_easy_strerror(res));
    curl_easy_cleanup(curl);
  }
 
  curl_global_cleanup();
}

void send_p(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream)){
    
    s_check_in(act);
    curl = curl_easy_init();
    CURLcode res;
    char url[150];
    sprintf(url,"%s://%s/%s/%s",f_server_config._protocol, f_server_config._server, path[act], token);
    
    if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION,debug_response);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, parms);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&act);
    curl_easy_setopt(curl, CURLOPT_PORT, f_server_config._port);
    res = curl_easy_perform(curl);
    
    if(res != CURLE_OK)
    fprintf(stderr, "failed to connect to server: %s\n",curl_easy_strerror(res));
    curl_easy_cleanup(curl);
    }
 
  curl_global_cleanup();
}

bool s_test_connection(){
  jsmntok_t token[3];
  jsmn_parser parser;
  jsmn_init(&parser);
  send_g(f_test,f_server_config._api_key,NULL,data_callback);
  if(response != NULL){
    
    int r = jsmn_parse(&parser, response, strlen(response), token, 3);
    
    if (r !=3 || token[0].type != JSMN_OBJECT){
      response = NULL;
      return false;
    }
    if(!jsoneq(response, &token[1], "status") && !jsoneq(response, &token[2], "connected")){
    response=NULL;
    return true;
      
    }
  }
  return false;

} 

void s_check_in (action act){
  jsmntok_t token[5];
  jsmn_parser parser;
  jsmn_init(&parser);

  if (checkedin || act == f_test)
    return; 
  else{
    char parms[strlen("md5=&crc32=&sha1=") + strlen(hashes.f_md5) + sizeof(hashes.f_crc32) + strlen(hashes.f_sha1)];
    sprintf( parms,"md5=%s&crc32=%d&sha1=%s", hashes.f_md5, hashes.f_crc32, hashes.f_sha1);
    checkedin = true;
    send_p(f_checkin, f_server_config._api_key, parms , data_callback);
   
    if (response != NULL){
      int r = jsmn_parse(&parser, response, strlen(response), token, 5);
      if (r !=5 || token[0].type != JSMN_OBJECT){
        printf("checkin error: error parsing response from server!\n");
        response = NULL;
        checkedin = false;
        return;
      }

      if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f'){
        response=NULL;
        return;
      } 
      else if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 't'){
        int size = token[4].end - token[4].start;
        char* error_msg = (char*) malloc(size);
        strncpy(error_msg,response+token[4].start,size);
        memset(error_msg+size, '\0',1);
        printf("checkin error: %s\n",error_msg);
      }
      response =NULL;
      checkedin = false;
      return;
    }
  }
}

void s_history(char** metadata_id, int size){ 
  char parms[strlen("metadata=[]") + 27*size + (size-1)];
  char tmp[28];

  int MAX_history = 10;
  int ntoken = 5 + (5 + 8*MAX_history)*size;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  sprintf( parms,"metadata=[");
  
  for(int i=0; i<size ; ++i){
    if(i > 0){
      sprintf(tmp,",\"%s\"", metadata_id[i]);
      strcat( parms,tmp);
    }
    else{
      sprintf(tmp,"\"%s\"", metadata_id[i]);
      strcat( parms,tmp);
    }
  }
  strcat(parms,"]");
  send_p(f_history, f_server_config._api_key, parms, data_callback);
  
  if (!response){
    printf("Error receiving response from server!\n");
    return NULL;
  }
  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  
  if (token[0].type != JSMN_OBJECT){
    printf("Error parsing response from server!\n");
    response = NULL;
    return NULL;
  }

// TODO: implement the parser of the histoy
  return NULL;

}

void s_get(char** metadata_id, int size){
  char parms[strlen("metadata=[]") + 27*size + (size-1)];
  char tmp[28];

  int MAX_history = 10;
  int ntoken = 5 + (5 + 8*MAX_history)*size;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  sprintf( parms,"metadata=[");
  
  for(int i=0; i<size ; ++i){
    if(i > 0){
      sprintf(tmp,",\"%s\"", metadata_id[i]);
      strcat( parms,tmp);
    }
    else{
      sprintf(tmp,"\"%s\"", metadata_id[i]);
      strcat( parms,tmp);
    }
  }
  strcat(parms,"]");
  send_p(f_get, f_server_config._api_key, parms, data_callback);
  
  if (!response){
    printf("Error receiving response from server!\n");
    return NULL;
  }
  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  
  if (token[0].type != JSMN_OBJECT){
    printf("Error parsing response from server!\n");
    response = NULL;
    return NULL;
  }

// TODO: implement the parser of the get
  return NULL;


}

RespCreated s_created(){
  printf("retreiving created metadata...\n");
  int page = 1;
  int pages = 0;
  int first_time = true;

  int ntoken = 9 + 12*20;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  int total_size=0;
  RespCreated* resp_created;
  RespCreated metadata_array; 
  metadata_array.size = 0;
  metadata_array.metadata = NULL;
  while(first_time || page<=pages){
   
    char parms[2];
    parms[0] = '/';
    parms[1] = page + '0';
    send_g(f_created,f_server_config._api_key,parms,data_callback);

    
    if (!response){
      printf("Error receiving response from server!\n");
      break;
    }
    
    int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
    
    if (token[0].type != JSMN_OBJECT){
      printf("Error parsing response from server!\n");
      response = NULL;
      break;
    }

    resp_created = dump_created(response,token);
      
    if (resp_created == NULL){
      printf("Malformed response!\n");
      response = NULL;
      break;
    }
    else{
      if(first_time)
        pages = resp_created->pages;
      
      if(resp_created->metadata && resp_created->size){
        total_size += resp_created->size;
        metadata_array.metadata = (MetadataServer*)realloc(metadata_array.metadata,sizeof(MetadataServer)*total_size);
        if (metadata_array.metadata){
          memcpy((metadata_array.metadata)+ metadata_array.size , resp_created->metadata , resp_created->size);
          metadata_array.size = total_size;
        }
      }
    }
    page++;
    if (first_time)
      first_time =false;
    
    free(resp_created);       
    response = NULL;


  }
  return metadata_array;
}

void s_add(Metadata metadata){

}

void s_scan(Metadata metadata){
  
}

bool s_applied(char* metadata_id){
  int ntoken = 5;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);
  
  char parms[strlen("md5=&crc32=&id=") + strlen(hashes.f_md5) + strlen(metadata_id) + sizeof(hashes.f_crc32)];
  sprintf( parms,"md5=%s&crc32=%d&id=%s", hashes.f_md5, hashes.f_crc32,metadata_id);

  send_p(f_applied,f_server_config._api_key, parms, data_callback);

    if (!response){
      printf("applied : error receiving response from server!\n");
      response = NULL;
      return false;
    }

  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (r !=ntoken || token[0].type != JSMN_OBJECT){
    printf("applied: error parsing response from server!\n");
    response = NULL;
    return false;
  }
  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_PRIMITIVE && *(response + token[4].start) == 't'){
    response=NULL;
    return true;
  }

  return false;

}

bool s_unapplied(char* metadata_id){
  int ntoken = 5;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  char parms[strlen("md5=&crc32=&id=") + strlen(hashes.f_md5) + strlen(metadata_id) + sizeof(hashes.f_crc32)];
  sprintf( parms,"md5=%s&crc32=%d&id=%s", hashes.f_md5, hashes.f_crc32,metadata_id);


  send_p(f_unapplied,f_server_config._api_key, parms, data_callback);

  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (r !=ntoken || token[0].type != JSMN_OBJECT){
    printf("applied: error parsing response from server!\n");
    response = NULL;
    return false;
  }
  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_PRIMITIVE && *(response + token[4].start) == 't'){
    response=NULL;
    return true;
  }

  return false;
}


bool s_delete(char* metadata_id){

  int ntoken = 5;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  char parms[strlen(metadata_id)+1];
  sprintf( parms,"/%s", metadata_id);
  send_g(f_delete,f_server_config._api_key, parms, data_callback);
  if (!response){
      printf("delete : error receiving response from server!\n");
      response = NULL;
      return false;
    }

  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (r !=ntoken || token[0].type != JSMN_OBJECT){
    printf("delete: error parsing response from server!\n");
    response = NULL;
    return false;
  }
  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "deleted")  && token[4].type == JSMN_PRIMITIVE && *(response + token[4].start) == 't'){
    response=NULL;
    return true;
  }

  return false;
} 


























//setters and getters
static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    FS_config* config = (FS_config*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0
    if (MATCH("server", "server")) {
        config->_server = strdup(value);
    } else if (MATCH("server", "port")) {
        config->_port = atoi(value);
    } else if (MATCH("server", "protocol")) {
        config->_protocol = strdup(value);
    } else if (MATCH("server", "verify")) {
        config->_verify = (bool)atoi(value);
    } else if (MATCH("server", "auth")) {
        config->_auth = (bool)atoi(value);
    } else if (MATCH("user", "key")) {
        config->_api_key = strdup(value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


bool f_set_config() 
{
  char *homedir = NULL;
  homedir = (char*)malloc(strlen(getenv("HOME"))+ strlen("/root/.config/first/first.config"));
  strcpy(homedir,getenv("HOME"));
  homedir = strcat(homedir,"/.config/first/first.config");

  if (ini_parse(homedir, handler, &f_server_config) < 0) {
        printf("Can't load configuration file!\n");
        return 1;
    }
}


void set_hashes(RCore *core)
{

  hashes.f_md5 = (char* )r_config_get(core->config, "file.md5");
  hashes.f_sha1 = (char* )r_config_get(core->config, "file.sha1");;

  ut64 crc32;
  ut8 *buf = NULL;
  int buf_len = 0;

  RCoreFile *cf = r_core_file_cur (core);
  RIODesc *desc = cf ? r_io_desc_get (core->io, cf->fd) : NULL;
  char* file = desc->name;
  buf = (ut8 *) r_file_slurp (file, &buf_len);
  crc32 = r_hash_crc_preset (buf, buf_len,CRC_PRESET_32);
  hashes.f_crc32 = (int)crc32;
  hashes.f_sha256 = "";
  return;
}



char* get_token(){
  return f_server_config._api_key;
}














char* get_arch(RCore* core){
  char bits[3] = "32";
  char* arch = NULL;

  RBinInfo* bin = NULL;
  bin = r_bin_get_info(core->bin);

  if(bin){
    if (bin->bits == 64)
      strcpy(bits,"64");
    arch = malloc(strlen(bin->arch)+2);
    if (!arch)
      return NULL;
    strcpy(arch, bin->arch);
    
    if (strstr(arch,"x86")){
      strcpy(arch, "intel");
      strcat(arch,bits);
    }
    else if (strstr(arch,"arm")){
      strcpy(arch, "arm");
      strcat(arch,bits);
    }
    else if (strstr(arch,"sparc"))
      strcpy(arch, "sparc");
    else if (strstr(arch,"ppc"))
      strcpy(arch, "ppc");
    
    return arch;    
  

  }
    
  return NULL;
}

char* get_signature(RCore* core, const RAnalFunction* fcn){
  if(!fcn)
    return NULL;
  char address[18];
  sprintf(address,"p8 $FS @0x%08x", fcn->addr);
  return r_core_cmd_str(core,address);
}


char** get_apis(RCore* core, RAnalFunction* fcn, int* size){
  if (!fcn)
    return NULL;
  int i=0;
  
  RBinInfo *info = r_bin_get_info (core->bin);
  RBinObject *obj = r_bin_cur_object (core->bin);
  bool lit = info ? info->has_lit: false;
  int va = core->io->va || core->io->debug;

  RListIter *iter;
  RBinImport *imp;
  if (!obj) {
    return NULL;
  }
  char** imports = (char**)malloc(sizeof(char*)*obj->imports->length);

  if (!imports)
    return NULL;

  r_list_foreach (obj->imports, iter, imp) {
    imports[i] = (char*)malloc(strlen(imp->name));
    if (imports[i])
      strncpy(imports[i],imp->name,strlen(imp->name));
    i++;
  }
  
  int imp_size = i;
  i=0;

  RAnalRef *refi;
  RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
  char** xrefs = (char**)malloc(sizeof(char*)*refs->length);
  
  if (xrefs)
    r_list_foreach (refs, iter, refi) {
      RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
      const char *name = f ? f->name: "";
      for (int j = 0; j < imp_size; ++j)
        if (strstr(name,imports[j])){ // radare2 add function type before the name for imported fncts 
          xrefs[i] = malloc(strlen(imports[j]));
          if (xrefs[i])
            strncpy(xrefs[i], imports[j],strlen(imports[j]));
          ++i;
        }
    }


  for (int j = 0; j < imp_size; ++j)
    if (imports[j])
      free(imports[j]);
  free(imports);
  *size = i;  
  if(!i)
    return NULL;

  return xrefs;
}