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
RespCreated* resp_created=NULL;

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

void dump_created_metadata(char* r, jsmntok_t* t, int j){
  for(int i=1;i<=(t->size)*2;i+=2){

    if(!jsoneq(r, t+i, "name") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* name = (char*) malloc(size);
      if (name == NULL)
      strncpy(name,r+(t+i+1)->start,(t+i+1)->end - (t+i+1)->start);
      memset(name+size, '\0',1);
      (resp_created->metadata+j)->name = name;
      continue;
    }
    
    if(!jsoneq(r, t+i, "prototype") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* prototype = (char*) malloc(size);
      strncpy(prototype,r+(t+i+1)->start,(t+i+1)->end - (t+i+1)->start);
      memset(prototype+size, '\0',1);
      (resp_created->metadata+j)->prototype = prototype;
      continue;
    }
    
    if(!jsoneq(r, t+i, "comment") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* comment = (char*) malloc(size);
      strncpy(comment,r+(t+i+1)->start,(t+i+1)->end - (t+i+1)->start);
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
void dump_created(char* r, jsmntok_t* t){
  int i=1;
  printf("%s\n", r);
  if (!jsoneq(r, t+i, "failed") && (t+i+1)->type == JSMN_PRIMITIVE && *(r+(t+i+1)->start) == 'f'){
    i+=2;
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
          dump_created_metadata(r,g,j);
          (resp_created->metadata+j)->address=-1;
          (resp_created->metadata+j)->creator=NULL;
          (resp_created->metadata+j)->similarity=0;
        }
      }
    }
  }
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

  if (f_server_config._api_key == ""){
    printf("%s\n","No api_key was set" );
    return false;
  }
  else
    send_g(f_test,f_server_config._api_key,NULL,data_callback);
    if(response != NULL){
      
      int r = jsmn_parse(&parser, response, strlen(response), token, 3);
      
      if (r !=3 || token[0].type != JSMN_OBJECT){
        printf("Error parsing response from server!\n");
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
  if (checkedin || act == f_test)
    return; 
  else{
    char parms[200];
    sprintf( parms,"md5=%s&crc32=%d&sha1=%s", hashes.f_md5, hashes.f_crc32, hashes.f_sha1);
    checkedin = true;
    send_p(f_checkin, f_server_config._api_key, parms , data_callback);
  }

}

// TODO: modify to an array
void s_history(char* metadata_id){ 
  char parms[strlen("metadata=")+24];
  sprintf( parms,"metadata=%s", metadata_id);
  send_p(f_history, f_server_config._api_key, parms, data_callback);
}

void s_get(){

}

MetadataServer* s_created(){
  printf("retreiving created metadata...\n");
  int page = 1;
  int pages = 0;
  int first_time = true;
  jsmntok_t token[9];
  jsmn_parser parser;
  jsmn_init(&parser);

  while(first_time || page<=pages){
   
    char parms[2];
    parms[0] = '/';
    parms[1] = page + '0';
    send_g(f_created,f_server_config._api_key,parms,data_callback);

    
    if (response == NULL){
      printf("Error receiving response from server!\n");
      break;
    }
    
    int r = jsmn_parse(&parser, response, strlen(response), token, 9);
    
    if (r !=9 || token[0].type != JSMN_OBJECT){
      printf("Error parsing response from server!\n");
      break;
    }

    dump_created(response,token);
      
    if (resp_created == NULL){
      printf("Malformed response!\n");
      break;
    }
    else{
      if(first_time)
        pages = resp_created->pages;
      
      if(resp_created->metadata != NULL && resp_created->size){
        printf("found metadata\n");
      }
    }
    page++;
    if (first_time)
      first_time =false;
    
    free(resp_created);       
    response =NULL;


  }
  return NULL;
}

void s_add(Metadata metadata){

}

void s_scan(Metadata metadata){
  
}

void s_applied(char* metadata_id){
  char parms[150];
  sprintf( parms,"md5=%s&crc32=%d&id=%s", hashes.f_md5, hashes.f_crc32,metadata_id);
  send_p(f_applied,f_server_config._api_key, parms, data_callback);
}

void s_unapplied(char* metadata_id){
  char parms[150];
  sprintf( parms,"md5=%s&crc32=%d&id=%s", hashes.f_md5, hashes.f_crc32,metadata_id);
  send_p(f_applied,f_server_config._api_key, parms, data_callback);
}


void s_delete(char* metadata_id){
  char parms[50];
  sprintf( parms,"/%s", metadata_id);
  send_g(f_delete,f_server_config._api_key, parms, data_callback);
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
  char *homedir = getenv("HOME");
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