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
char* response = NULL;






static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
  if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
      strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
    return 0;
  }
  return -1;
}

char* print_repeater(char a[],int n){
  for (int i = 0; i < n; ++i){
      a[i] = '_';
  }
  a[n] = '\0';
  return a;
}


char* parse_time(char a[]){
  a[10] = ' ';  
  for (int i = 19; i > 11; --i){
    char tmp = a[i];
    a[i] = a[i-1];
  }
  a[11]= '(';
  a[20]= ')';
  return a;
}

void print_line(int n){
  for (int i = 0; i < n; ++i){
    r_cons_printf("_");
  }
  r_cons_printf("\n");
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

bool dump_created_metadata(char* r, jsmntok_t* t, int j, RespCreated* resp_created){
  for(int i=1;i<=(t->size)*2;i+=2){

    if(!jsoneq(r, t+i, "name") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* name = (char*) malloc(size +1);
      if (name == NULL)
        return false;
      strncpy(name,r+(t+i+1)->start,size);
      memset(name+size, '\0',1);
      (resp_created->metadata+j)->name = strdup(name);
      free(name);
      continue;
    }
    
    if(!jsoneq(r, t+i, "prototype") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* prototype = (char*) malloc(size+1);
      if (prototype == NULL)
        return false;
      strncpy(prototype,r+(t+i+1)->start,size);
      memset(prototype+size, '\0',1);
      (resp_created->metadata+j)->prototype = strdup(prototype);
      free(prototype);
      continue;
    }
    
    if(!jsoneq(r, t+i, "comment") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* comment = (char*) malloc(size + 1);
      if (comment == NULL)
        return false;
      strncpy(comment,r+(t+i+1)->start,size);
      memset(comment+size, '\0',1);
      (resp_created->metadata+j)->comment = strdup(comment);
      free(comment);
      continue;
    }      
    
    if(!jsoneq(r, t+i, "rank") && (t+i+1)->type == JSMN_PRIMITIVE){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* rank = (char*) malloc(size +1 );
      if (rank == NULL)
        return false;
      strncpy(rank,r+(t+i+1)->start,size);
      memset(rank+size, '\0',1);
      (resp_created->metadata+j)->rank = atoi(rank);
      free(rank);
      continue;
    }     
    
    if(!jsoneq(r, t+i, "id") && (t+i+1)->type == JSMN_STRING){
      int size = (t+i+1)->end - (t+i+1)->start;
      char* id = (char*) malloc(size + 1);
      if (id == NULL)
        return false;
      strncpy(id,r+(t+i+1)->start,size);
      memset(id+size, '\0',1);
      (resp_created->metadata+j)->id = strdup(id);
      free(id);
      continue;
    }
  }
  return true;     
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
      i+=4;
      if (!jsoneq(r, t+i, "results") && (t+i+1)->type == JSMN_ARRAY && (t+i+1)->size){
        resp_created->size = (t+i+1)->size;
        resp_created->metadata = (MetadataServer*) malloc(sizeof(MetadataServer)*resp_created->size);
        int l = 0;
        for(int j=1;j<(resp_created->size)*13;j+=13){
          jsmntok_t* g = (t+i+j+1);
          if(g->type == JSMN_OBJECT && !dump_created_metadata(r,g,l,resp_created))
            return NULL;
          l++;
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
  if (http_code == 200 && act != f_applied){
    response = malloc (strlen((char*)ptr)+1);
    strcpy(response , (char*)ptr);
  }
  return size*nmemb;
}


bool send_g(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream))
{
  s_check_in(act);

  curl = curl_easy_init();
  CURLcode res;

  char url[strlen(f_server_config._protocol)+strlen(f_server_config._server)+strlen(path[act])+strlen(token) + (parms? strlen(parms) : 0)];
  sprintf(url,"%s://%s/%s/%s",f_server_config._protocol, f_server_config._server, path[act], token);
  if (parms != NULL)
    strcat(url,parms); 

  if(curl) {
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION,debug_response);
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&act);
    curl_easy_setopt(curl, CURLOPT_PORT, f_server_config._port);

    res = curl_easy_perform(curl);
    if(res != CURLE_OK){
      fprintf(stderr, "Curl: %s\n",curl_easy_strerror(res));
      return false;
    }
    curl_easy_cleanup(curl);
  }
 
  curl_global_cleanup();
  return true;
}

bool send_p(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream)){
    
    s_check_in(act);
    curl = curl_easy_init();
    CURLcode res;
    char url[150];
    sprintf(url,"%s://%s/%s/%s",f_server_config._protocol, f_server_config._server, path[act], token);
    
    if(curl) {
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
    // curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    // curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION,debug_response);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, parms);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&act);
    curl_easy_setopt(curl, CURLOPT_PORT, f_server_config._port);
    res = curl_easy_perform(curl);
    
    if(res != CURLE_OK){
      fprintf(stderr, "failed to connect to server: %s\n",curl_easy_strerror(res));
      return false;
    }
    curl_easy_cleanup(curl);
    }
 
  curl_global_cleanup();
  return true;
}

bool s_test_connection(){
  jsmntok_t token[3];
  jsmn_parser parser;
  jsmn_init(&parser);
  if(!send_g(f_test,f_server_config._api_key,NULL,data_callback))
    return false;
  if(response != NULL){
    
    int r = jsmn_parse(&parser, response, strlen(response), token, 3);
    
    if (r !=3 || token[0].type != JSMN_OBJECT){
      free(response);
      response = NULL;
      return false;
    }
    if(!jsoneq(response, &token[1], "status") && !jsoneq(response, &token[2], "connected")){
    free(response);
    response = NULL;
    return true;
      
    }
  }
  return false;

} 

void s_check_in (action act){
  jsmntok_t token[5];
  jsmn_parser parser;
  jsmn_init(&parser);

  if (checkedin || act == f_test || act == f_created || act == f_history)
    return; 
  else{
    char parms[strlen("md5=&crc32=&sha1=") + strlen(hashes.f_md5) + sizeof(hashes.f_crc32) + strlen(hashes.f_sha1)];
    sprintf( parms,"md5=%s&crc32=%d&sha1=%s", hashes.f_md5, hashes.f_crc32, hashes.f_sha1);
    checkedin = true;
    if(!send_p(f_checkin, f_server_config._api_key, parms , data_callback))
      return;
   
    if (response != NULL){
      int r = jsmn_parse(&parser, response, strlen(response), token, 5);
      if (r !=5 || token[0].type != JSMN_OBJECT){
        printf("checkin error: error parsing response from server!\n");
        free(response);
        response = NULL;
        checkedin = false;
        return;
      }

      if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f'){
        free(response);
        response = NULL;
        return;
      } 
      else if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 't'){
        int size = token[4].end - token[4].start;
        char* error_msg = (char*) malloc(size);
        strncpy(error_msg,response+token[4].start,size);
        memset(error_msg+size, '\0',1);
        printf("checkin error: %s\n",error_msg);
      }
      free(response);
      response = NULL;
      checkedin = false;
      return;
    }
  }
}

bool s_history(const char** metadata_id, int size){ 
  char parms[strlen("metadata=[]") + 27*size + (size-1)];
  char tmp[28];

  int MAX_history = 20;
  int ntoken = 5 + (5 + 9*MAX_history)*size;
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
  if(!send_p(f_history, f_server_config._api_key, parms, data_callback))
    return false;
  
  if (!response){
    printf("history: error receiving response from server!\n");
    return false;
  }

  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  
  if (token[0].type != JSMN_OBJECT){
    printf("history: error parsing response from server!\n");
    free(response);
    response = NULL;
    return false ;
  }
  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_OBJECT){
    jsmntok_t* t = &token[8];
  
    r_cons_printf("| %5s%-16s | %17s%-23s | %25s%-35s | %31s%-39s |\n"," ","Committed"," ","Name"," ","Prototype"," ","Comment");
    char a[73];
    r_cons_printf("|%s", print_repeater(a,23));
    r_cons_printf("|%s", print_repeater(a,42));
    r_cons_printf("|%s", print_repeater(a,62));
    r_cons_printf("|%s|\n", print_repeater(a,72));
    for(int i = 1 ; i < (t->size)*9 ; i+=9){

      jsmntok_t* tt = t+i;
      char name[41], proto[61], cmnt[71], time[22];
      for(int j = 1 ; j < (tt->size)*2 ; j+=2){
        int width=0;
        if(!jsoneq(response, tt+j, "name") && (tt+j)->type == JSMN_STRING){
          width = 40;
          memcpy(name, response+(tt+j+1)->start, ((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start));
          name[((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start)] = '\0';  
        }
        if(!jsoneq(response, tt+j, "prototype") && (tt+j)->type == JSMN_STRING){
          width = 60;
          memcpy(proto, response+(tt+j+1)->start, ((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start));
          proto[((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start)] = '\0';
        }
        if(!jsoneq(response, tt+j, "comment") && (tt+j)->type == JSMN_STRING){
          width = 70;
          memcpy(cmnt, response+(tt+j+1)->start, ((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start));
          cmnt[((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start)] = '\0';
        }
        if(!jsoneq(response, tt+j, "committed") && (tt+j)->type == JSMN_STRING){
          width = 21;
          memcpy(time, response+(tt+j+1)->start, ((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start));
          time[((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start)] = '\0';
        }
      }    
      r_cons_printf("| %-21.21s " ,parse_time(time));
      r_cons_printf("| %-40.40s " ,name);
      r_cons_printf("| %-60.60s " ,proto);
      r_cons_printf("| %-70.70s |\n" ,cmnt);

    }
  }
  free(response);
  response = NULL;

  return true;

}

void s_get(char** metadata_id,int* address, int size, MetadataServer* m){
  char parms[strlen("metadata=[]") + 27*size + (size-1)];
  char tmp[28];

  int MAX_GET = 20;
  int ntoken = 5 + 14*size;
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
  if(!send_p(f_get, f_server_config._api_key, parms, data_callback))
    return;
  if (!response){
    printf("get: error receiving response from server!\n");
    return ;
  }

  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  
  if (token[0].type != JSMN_OBJECT){
    printf("get: error parsing response from server!\n");
    free(response);
    response = NULL;
    return ;
  }
  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_OBJECT){
    jsmntok_t* t = &token[4];
  

    for(int i = 1 ; i < (t->size)*14 ; i+=14){
      int sz = (t+i)->end - (t+i)->start;
      char id[sz + 1];
      strncpy(id,response+(t+i)->start,sz);
      id[sz] = '\0';
      int k;
      for (k = 0; k < size; ++k)
        if( strstr(*(metadata_id+k), id))
          break;
      if(k == size)
        return;
      if (address)
        r_cons_printf("| 0x%08x |", *(address+k));
  
      jsmntok_t* tt = t+i+1;
      for(int j = 1 ; j < (tt->size)*2 ; j+=2){
        int width=0;
        if(!jsoneq(response, tt+j, "name") && (tt+j)->type == JSMN_STRING){
          if (m){
            int size = (tt+j+1)->end - (tt+j+1)->start ;
            m->name = malloc(size+1);
            if (!m->name)
              return;
            memcpy(m->name, response+(tt+j+1)->start, size);
            memset(m->name + size,'\0', 1);
          }
          width = 40;
        }
        if(!jsoneq(response, tt+j, "prototype") && (tt+j)->type == JSMN_STRING){
          if (m){
            int size = (tt+j+1)->end - (tt+j+1)->start ;
            m->prototype = malloc(size+1);
            if (!m->prototype)
              return;
            memcpy(m->prototype, response+(tt+j+1)->start, size);
          }
          width = 60;
        }
        if(!jsoneq(response, tt+j, "comment") && (tt+j)->type == JSMN_STRING){
          if (m){
            int size = (tt+j+1)->end - (tt+j+1)->start ;
            m->comment = malloc(size+1);
            if (!m->comment)
              return;
            memcpy(m->comment, response+(tt+j+1)->start, size);
          }
          width = 70;
        }
        if(!jsoneq(response, tt+j, "creator") && (tt+j)->type == JSMN_STRING)
          width = 20;
        if(!jsoneq(response, tt+j, "rank")&& (tt+j)->type == JSMN_STRING)
          width = 4;
        if(width && !m)
          r_cons_printf(" %-*.*s |", width, ((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start) ,response+(tt+j+1)->start );
      }
      if(!m)     
        r_cons_printf("\n");

    }
  }
  else
    eprintf("failed to get data");
  free(response);
  response = NULL;

}

  

bool s_add(Metadata metadata[], int size, char* arch){
  int ntoken = 5 + size*2;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);
  // r_cons_printf("The following functions will be added:\n");

  int l = snprintf(NULL,0, "md5=%s&crc32=%d&functions={%s}", hashes.f_md5, hashes.f_crc32);
  char* parms = malloc(l+1);
  if(!parms )
    return false;
  snprintf(parms,l+1,"md5=%s&crc32=%d&functions={%s}",hashes.f_md5, hashes.f_crc32,"%s");

  for (int i=0; i< size; i++){ 
    Metadata m = metadata[i];

    // r_cons_printf("\tname = %s\n", m.name );

    int s = snprintf(NULL,0,"\"%d\": {\"comment\": \"%s\", \"opcodes\": \"%s\", \"name\": \"%s\", \"apis\" : [%s] , \"architecture\": \"%s\", \"prototype\": \"%s\"}",\
      m.address, m.comment, m.signature, m.name, "%s" , arch, m.prototype);
    char* functions = malloc(s+5);
    if (!functions)
      return false;
    if (!m.apis_size)
      snprintf(functions,s+1,"\"%d\": {\"comment\": \"%s\", \"opcodes\": \"%s\", \"name\": \"%s\", \"apis\" : [%s] , \"architecture\": \"%s\", \"prototype\": \"%s\"}",\
        m.address, m.comment, m.signature, m.name, "" , arch, m.prototype);
    else{
      snprintf(functions,s+1,"\"%d\": {\"comment\": \"%s\", \"opcodes\": \"%s\", \"name\": \"%s\", \"apis\" : [%s] , \"architecture\": \"%s\", \"prototype\": \"%s\"}",\
        m.address, m.comment, m.signature, m.name, "%s" , arch, m.prototype);
      
      int aps = snprintf(NULL, 0 ,"\"%s\"", m.apis[0]);
      char* apis = malloc(aps+7);
      if(!apis)
        return false;
      snprintf(apis,aps+1 ,"\"%s\"" ,m.apis[0]);
      for (int ap=1; ap < m.apis_size; ++ap){
        strcat(apis, ", \"%s\"");
        aps = snprintf(NULL,0,apis, m.apis[ap]);
        char* apis_tmp = malloc(aps +1);
        snprintf(apis_tmp,aps+1,apis, m.apis[ap]);
        apis = realloc(apis, aps+7);
        strcpy(apis,apis_tmp);
        free(apis_tmp);
      }

      int as = snprintf(NULL,0,functions, apis);
      char* at = malloc(as+1);
      if(!at)
        return false;
      snprintf(at,as+1, functions, apis);
      functions = realloc(functions, as+5);
      strcpy(functions, at);
      free(at);
    }      
      
    l = snprintf(NULL,0,parms,functions);

    if (i < size - 1){
      strcat(functions, ", %s");
      l+=4;      
    }
    char* tmp = malloc(l+1);
    if(!tmp )
      return false;
    snprintf(tmp,l+1,parms, functions);
    parms = realloc(parms, l+1);
    if (!parms)
      return false;
    strncpy(parms,tmp,l+1);
    free(tmp);
    free(functions);
  }
if(!send_p(f_add,f_server_config._api_key, parms, data_callback))
  return false;
free(parms);
if (!response){
  eprintf("add : error receiving response from server!\n");
  return false;
  }
  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (r !=ntoken || token[0].type != JSMN_OBJECT){
    eprintf("add: error parsing response from server!\n");
    free(response);
    response = NULL;
    return false;
  }
  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_OBJECT){
    jsmntok_t* t = &token[4];
    for(int i = 1 ; i < (t->size)*2 ; i+=2){
      if((t+i)->type == JSMN_STRING && (t+i+1)->type == JSMN_STRING){
        int sz1 = (t+i)->end - (t+i)->start;
        int sz2 = (t+i+1)->end - (t+i+1)->start;
        char addr[sz1 + 1];
        char id[sz2 + 1];
        strncpy(addr,response+(t+i)->start,sz1);
        strncpy(id,response+(t+i+1)->start,sz2);
        addr[sz1] = '\0';
        id[sz2] = '\0';
        int addr_int = atoi(addr);

        s_applied(id);

        DBdata d;
        strncpy(d.id, id,25);
        d.id[25]= '\0';
        d.address = addr_int;
        d.deleted = false;
        save(d);

      }
    }
    free(response);
    response=NULL;
    return true;
  }
  free(response);
  response = NULL;
  return false;

}

bool s_scan(Metadata metadata[], int size, char* arch ){
  int MAX_scan = 20;
  int MAX_engines = 10;
  int ntoken = 9 + 2 * MAX_engines + size*(2 + 17 * MAX_scan);
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  int l = snprintf(NULL,0, "md5=%s&crc32=%d&functions={%s}", hashes.f_md5, hashes.f_crc32);
  char* parms = malloc(l+1);
  if(!parms )
    return false;
  snprintf(parms,l+1,"md5=%s&crc32=%d&functions={%s}",hashes.f_md5, hashes.f_crc32,"%s");

  for (int i=0; i< size; i++){ 
    Metadata m = metadata[i];


    int s = snprintf(NULL,0,"\"%d\": {\"opcodes\": \"%s\", \"architecture\": \"%s\", \"apis\" : [%s]}",\
      m.address,  m.signature, arch, "%s" );
    char* functions = malloc(s+5);
    if (!functions)
      return false;
    if (!m.apis_size)
      snprintf(functions,s+1,"\"%d\": {\"opcodes\": \"%s\", \"architecture\": \"%s\", \"apis\" : [%s]}",\
        m.address,m.signature, arch,"" );
    else{
      snprintf(functions,s+1,"\"%d\": {\"opcodes\": \"%s\", \"architecture\": \"%s\", \"apis\" : [%s]}",\
        m.address,m.signature, arch, "%s");      

      int aps = snprintf(NULL, 0 ,"\"%s\"", m.apis[0]);
      char* apis = malloc(aps+7);
      if(!apis)
        return false;
      snprintf(apis,aps+1 ,"\"%s\"" ,m.apis[0]);
      for (int ap=1; ap < m.apis_size; ++ap){
        strcat(apis, ", \"%s\"");
        aps = snprintf(NULL,0,apis, m.apis[ap]);
        char* apis_tmp = malloc(aps +1);
        snprintf(apis_tmp,aps+1,apis, m.apis[ap]);
        apis = realloc(apis, aps+7);
        strcpy(apis,apis_tmp);
        free(apis_tmp);
      }

      int as = snprintf(NULL,0,functions, apis);
      char* at = malloc(as+1);
      if(!at)
        return false;
      snprintf(at,as+1, functions, apis);
      functions = realloc(functions, as+5);
      strcpy(functions, at);
      free(at);
    }      
      
    l = snprintf(NULL,0,parms,functions);

    if (i < size - 1){
      strcat(functions, ", %s");
      l+=4;      
    }
    char* tmp = malloc(l+1);
    if(!tmp )
      return false;
    snprintf(tmp,l+1,parms, functions);
    parms = realloc(parms, l+1);
    if (!parms)
      return false;
    strncpy(parms,tmp,l+1);
    free(tmp);
    free(functions);
  }

if(!send_p(f_scan,f_server_config._api_key, parms, data_callback))
  return false;
free(parms);
if (!response){
  eprintf("scan : error receiving response from server!\n");
  return false;
  }
  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (token[0].type != JSMN_OBJECT){
    eprintf("scan: error parsing response from server!\n");
    free(response);
    response = NULL;
    return false;
  }

  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_OBJECT){
    jsmntok_t* t = &token[6];
    int fnc_count = t->size;
    t++;
    while(fnc_count){
      int seen = 0;
      bool incremented = false;
      int size = (t)->end - (t)->start;
      char address[size+1];
      memcpy(address, response + t->start, size);
      address[size] = '\0';
      int addr = atoi(address);
      
      print_line(150);
      r_cons_printf("Address = 0x%08x\t", addr);
      
      t = t+1;
      int i = 2;
      int array_size = t->size;
      r_cons_printf("Matches = %d\n", array_size);
      print_line(150);
      while (seen != array_size){
        if (incremented){
          print_line(150);
          incremented = false;
        }


        if(!jsoneq(response, t+i, "comment")){
          size = (t+i+1)->end - (t+i+1)->start;
          char comment[size+1];
          memcpy(comment, response + (t+i+1)->start, size);
          comment[size] = '\0';
          i+=2;
          r_cons_printf("\t| %-12s | %s\n","Comment", comment);
        }
        if(!jsoneq(response, t+i, "name")){
          size = (t+i+1)->end - (t+i+1)->start;
          char name[size+1];
          memcpy(name, response + (t+1+i)->start, size);
          name[size] = '\0';
          i+=2;
          r_cons_printf("\t| %-12s | %s\n","Name", name);
        }
        if(!jsoneq(response, t+i, "creator")){
          size = (t+i+1)->end - (t+i+1)->start;
          char creator[size+1];
          memcpy(creator, response + (t+i+1)->start, size);
          creator[size] = '\0';
          i+=2;
          r_cons_printf("\t| %-12s | %s\n","Creator", creator);
        }
        if(!jsoneq(response, t+i, "similarity")){
          size = (t+i+1)->end - (t+i+1)->start;
          char similarity[size+1];
          memcpy(similarity, response + (t+i+1)->start, size);
          similarity[size] = '\0';
          i+=2;
          r_cons_printf("\t| %-12s | %s\n","Similarity", similarity);
        }
        if(!jsoneq(response, t+i, "rank")){
          size = (t+i+1)->end - (t+i+1)->start;
          char rank[size+1];
          memcpy(rank, response + (t+1+i)->start, size);
          rank[size] = '\0';
          i+=2;
          r_cons_printf("\t| %-12s | %s\n","Rank", rank);
        }
        if(!jsoneq(response, t+i, "prototype")){
          size = (t+i+1)->end - (t+i+1)->start;
          char prototype[size+1];
          memcpy(prototype, response + (t+i+1)->start, size);
          prototype[size] = '\0';
          i+=2;
          r_cons_printf("\t| %-12s | %s\n","Prototype", prototype);
        }
        if(!jsoneq(response, t+i, "engines")){
          r_cons_printf("\t| %-12s | ","Engines");
          int eng_count = (t+i+1)->size;
          for (int k = 1 ; k <= eng_count; k++){
            size = (t+i+1+k)->end - (t+i+1+k)->start;
            char eng[size+1];
            memcpy(eng, response + (t+i+1+k)->start, size);
            eng[size] = '\0';
            r_cons_printf("%s\t", eng);

          }
          i+=(eng_count+2);
          r_cons_printf("\n");
        }
        if(!jsoneq(response, t+i, "id")){
          incremented = true;
          seen++;
          size = (t+i+1)->end - (t+i+1)->start;
          char id[size+1];
          memcpy(id, response + (t+i+1)->start, size);
          id[size] = '\0';
          seen == array_size ? (i+=2) : (i+=3);
          r_cons_printf("\t| %-12s | %s\n","ID", id);
        }
      }
      if(array_size)
        t += i;
      else 
        t += 1;

      fnc_count--;
      r_cons_printf("\n");
    }
    free(response);
    response = NULL;
    return true;
  }
  free(response);
  response = NULL;
  return false;
}





void s_applied(const char* metadata_id){
  int ntoken = 5;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);
  
  char parms[strlen("md5=&crc32=&id=") + strlen(hashes.f_md5) + strlen(metadata_id) + sizeof(hashes.f_crc32)];
  sprintf( parms,"md5=%s&crc32=%d&id=%s", hashes.f_md5, hashes.f_crc32,metadata_id);

  if(!send_p(f_applied,f_server_config._api_key, parms, data_callback))
    return;

}

bool s_unapplied(char* metadata_id){
  int ntoken = 5;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  char parms[strlen("md5=&crc32=&id=") + strlen(hashes.f_md5) + strlen(metadata_id) + sizeof(hashes.f_crc32)];
  sprintf( parms,"md5=%s&crc32=%d&id=%s", hashes.f_md5, hashes.f_crc32,metadata_id);


  if(!send_p(f_unapplied,f_server_config._api_key, parms, data_callback))
    return false;
  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (r !=ntoken || token[0].type != JSMN_OBJECT){
    printf("applied: error parsing response from server!\n");
    free(response);
    response = NULL;
    return false;
  }
  if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_PRIMITIVE && *(response + token[4].start) == 't'){
    free(response);
    response=NULL;
    return true;
  }

  return false;
}


bool s_delete(const char* metadata_id){

  int ntoken = 5;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);

  char parms[strlen(metadata_id)+1];
  sprintf( parms,"/%s", metadata_id);
  if(!send_g(f_delete,f_server_config._api_key, parms, data_callback))
    return false;
  if (!response){
      printf("delete : error receiving response from server!\n");
      free(response);
      response = NULL;
      return false;
    }

  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (r !=ntoken || token[0].type != JSMN_OBJECT){
    printf("delete: error parsing response from server!\n");
    free(response);
    response = NULL;
    return false;
  }
  if(!jsoneq(response, &token[3], "failed") && token[4].type == JSMN_PRIMITIVE && *(response + token[4].start) == 'f' && !jsoneq(response, &token[1], "deleted")  && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 't'){
    free(response);
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
  homedir = (char*)malloc(strlen(getenv("HOME"))+strlen("/.config/first/first.config"));
  strcpy(homedir,getenv("HOME"));
  
  DIR* dir;
  
  dir = opendir(strcat(homedir,"/.config/first"));

  if (!dir){
    printf("Can't load configuration file!\n");
    return false;
  }
  closedir(dir);

  if (ini_parse(strcat(homedir,"/first.config"), handler, &f_server_config) < 0) {
        eprintf("Can't load configuration file!\n");
        return false;
    }
  return true;
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
  char* result = r_core_cmd_str(core,address);
  result[strlen(result)-1]='\0';
  return result;
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
  char* imports[obj->imports->length];

  r_list_foreach (obj->imports, iter, imp) {
    imports[i] = (char*)malloc(strlen(imp->name)+1);
    if (imports[i])
      strcpy(imports[i],imp->name);
    i++;
  }
  
  int imp_size = i;
  i=0;

  RAnalRef *refi;
  RList *refs = r_anal_fcn_get_refs (core->anal, fcn);
  char* xrefs[refs->length];
  
  r_list_foreach (refs, iter, refi) {
    RFlagItem *f = r_flag_get_at (core->flags, refi->addr, true);
    const char *name = f ? f->name: "";
    bool exist = false;
    for (int j = 0; j < imp_size; ++j)
      if (strstr(name,imports[j])){ // radare2 add function type before the name for imported fncts 
        for (int k = 0; k < i; ++k)
          if (!strcmp(imports[j],xrefs[k])){
            exist = true;
            break; 
          }
        if(!exist){
          xrefs[i] = malloc(strlen(imports[j])+1);
          if (xrefs[i]){
            strcpy(xrefs[i], imports[j]);
          }
          ++i;
        }
      break;
      }
  }
    


  for (int j = 0; j < imp_size; ++j)
    if (imports[j])
      free(imports[j]);
  *size = i;  
  if(!i)
    return NULL;
  char** apis = (char**)malloc(sizeof(char*)*i);
  if(!apis)
    return NULL;
  memcpy(apis,xrefs,sizeof(char*)*i);
  return apis;
}

char* get_prototype(RCore *core, RAnalFunction *fcn){
  if (!fcn)
    return NULL;
  char cmd[6+strlen(fcn->name)];
  sprintf(cmd, "afcf %s",fcn->name);
  char* result = r_core_cmd_str(core, cmd);
  result[strlen(result)-1]='\0';
  return result;
}

char* get_comment(RCore *core, RAnalFunction *fcn){
  char cmd[15];
  sprintf(cmd, "CC. 0x%08x",fcn->addr); 
  char* result = r_core_cmd_str(core, cmd);
  result[strlen(result)-1]='\0';
  return result;
}


bool set_comment(RCore *core, RAnalFunction *fcn, const char* comment){
  if (!comment)
    return false;

  char cmd[16 + strlen(comment)];
  sprintf(cmd, "CC %s @0x%08x",comment,fcn->addr);
  return r_core_cmd0(core, cmd);
}













// doers
bool do_add(RCore* core, RAnalFunction *fcn){
  Metadata m;
  m.address = (int)fcn->addr;
  char* opcodes = get_signature(core, fcn);
  m.signature = r_base64_encode_dyn(opcodes,strlen(opcodes));
  m.name = fcn->name;
  m.prototype = get_prototype(core, fcn);
  m.comment = get_comment(core, fcn);
  int size = 0;
  m.apis = get_apis(core, fcn, &size);
  m.apis_size = size;
  
  Metadata metadata[1];
  metadata[0] = m;
  s_add(metadata,1, get_arch(core)); 
  r_cons_printf("Done\n");
  for (int i = 0; i < size; ++i)
    free(m.apis[i]);
  free(m.apis);
}


bool do_add_all(RCore* core, RList* fcns, const char* comm){
  RListIter *iter;
  RAnalFunction *fcn;
  Metadata metadata[fcns->length];
  int i = 0;
  r_list_foreach (fcns, iter, fcn) {
    Metadata m;
    m.address = (int)fcn->addr;
    char* opcodes = get_signature(core, fcn);
    m.signature = r_base64_encode_dyn(opcodes,strlen(opcodes));
    m.name = fcn->name;
    m.prototype = get_prototype(core, fcn);
    if (!comm)
      m.comment = get_comment(core, fcn);
    else{
      char comment[strlen(get_comment(core, fcn)) + strlen(comm) + 3];
      strcpy(comment, get_comment(core, fcn));
      strcat(comment, " ");
      strcat(comment, comm);
      m.comment = strdup(comment);
    }
    int size = 0;
    m.apis = get_apis(core, fcn, &size);
    m.apis_size = size;
    
    metadata[i++] = m;
    // make max 20  
  }
  int j = 0;
  while (i > 0){
    s_add(&metadata[j], i > 19? 20 : i ,get_arch(core));
    j += 20;
    i -= 20;
  }
  r_cons_printf("Done\n");


  for (int i=0; i < fcns->length; ++i){
    for (int j = 0; j < metadata[i].apis_size ; ++j)
      free(metadata[i].apis[j]);
    free(metadata[i].apis);
  }
}


bool do_scan(RCore* core, RAnalFunction *fcn){
  Metadata m;
  m.address = (int)fcn->addr;
  char* opcodes = get_signature(core, fcn);
  m.signature = r_base64_encode_dyn(opcodes,strlen(opcodes));
  int size = 0;
  m.apis = get_apis(core, fcn, &size);
  m.apis_size = size;
  
  Metadata metadata[1];
  metadata[0] = m;
  s_scan(metadata,1, get_arch(core)); 
  for (int i = 0; i < size; ++i)
    free(m.apis[i]);
  free(m.apis);
}


bool do_scan_all(RCore* core, RList* fcns){
  RListIter *iter;
  RAnalFunction *fcn;
  Metadata metadata[fcns->length];
  int i = 0;
  r_list_foreach (fcns, iter, fcn) {
    Metadata m;
    m.address = (int)fcn->addr;
    char* opcodes = get_signature(core, fcn);
    m.signature = r_base64_encode_dyn(opcodes,strlen(opcodes));
    int size = 0;
    m.apis = get_apis(core, fcn, &size);
    m.apis_size = size;
    
    metadata[i++] = m;
    // make max 20  
  }
  int j = 0;
  while (i > 0){
    s_scan(&metadata[j], i > 19? 20 : i ,get_arch(core));
    j += 20;
    i -= 20;
  }


  for (int i=0; i < fcns->length; ++i){
    for (int j = 0; j < metadata[i].apis_size ; ++j)
      free(metadata[i].apis[j]);
    free(metadata[i].apis);
  }
}




void do_get(){
  FILE* f;
  char *db_path = NULL;
  int address;
  char id[26];
  db_path = (char*)malloc(strlen(getenv("HOME"))+strlen("/.config/first/db/.dat") + strlen(hashes.f_md5) + 1);
  if (!db_path)
    return;
  strcpy(db_path,getenv("HOME"));
  strcat(db_path,"/.config/first/db/");
  strcat(db_path,hashes.f_md5);
  strcat(db_path,".dat");

  if( f = fopen(db_path,"r")){
    int i = 0;
    int* addr = NULL;
    char** mid = NULL;
    DBdata c;
    r_cons_printf("| %2s%-8s | %32s%-38s | %18s%-22s | %7s%-13s | %4s | %26s%-34s |\n"," ","Address"," ","Comment"," ","Name"," ","Creator","Rank"," ","Prototype");
    char a[83];
    r_cons_printf("|%s", print_repeater(a,12));
    r_cons_printf("|%s", print_repeater(a,72));
    r_cons_printf("|%s", print_repeater(a,42));
    r_cons_printf("|%s", print_repeater(a,22));
    r_cons_printf("|%s", print_repeater(a,6));
    r_cons_printf("|%s|\n", print_repeater(a,62));
    while (fread(&c, sizeof(DBdata),1,f) > 0 ){
      if (c.deleted)
        continue;
      addr = (int*)realloc( addr ,sizeof(int) * (i+1));
      mid = (char**)realloc( mid ,sizeof(char*) * (i+1));
      *(mid + i) = malloc(strlen(c.id)+1);
      *(addr + i) = c.address;
      strcpy( *(mid + i), c.id);
      ++i;
    }
    fclose(f);
    int j = 0;
    while (i > 0){
      s_get(&mid[j] ,&addr[j], i > 19? 20 : i,NULL);
      j += 20;
      i -= 20;
    }

  }

}






void do_delete(RCore* core,const int addr){


  char* id = delete_db(addr);
  if (id && s_delete(id)){
    RAnalFunction* fcn = r_anal_get_fcn_at(core->anal, (ut64)addr,0);
    if (fcn)
      r_cons_printf("Annotations of function %s of address 0x%08x are deleted\n", fcn->name, fcn->addr);
    else 
      r_cons_printf("Annotations of function of address 0x%08x are deleted\n", addr);
    free(id);
    return;
  }
  if(id)
    free(id);
  r_cons_printf("Deletion failed\n");
}


void do_delete_id(const char* id){
  if(delete_db_unknown_file(id)){
    if(s_delete(id))
      r_cons_printf("Succesfully deleted\n");
  }
  else{
    r_cons_printf("Function don't exist\n");
    r_cons_printf("Deletion failed\n");
  }

}


void do_history(const int addr){
 
  char* id = check_db(addr);

  if (id){
    const char* mid[1];
    mid[0] = id;
    if(s_history(mid, 1)){
  
    }
  free(id);
  }
  else
    r_cons_printf("Address is not identified\n");

}


void do_history_id(const char* id){
  if(check_db_unknown_file(id)){
    const char* mid[1];
    mid[0] = id;
    if(s_history(mid, 1)){

    }
  }
  else
    r_cons_printf("ID is not identified\n");
}



void do_created(){
  r_cons_printf("| %12s%-13s | %4s | %22s%-23s | %30s%-30s | %40s%-40s |\n"," ","ID","Rank"," ","Name"," ","Prototype"," ","Comment");
  char a[83];
  r_cons_printf("|%s", print_repeater(a,27));
  r_cons_printf("|%s", print_repeater(a,6));
  r_cons_printf("|%s", print_repeater(a,47));
  r_cons_printf("|%s", print_repeater(a,62));
  r_cons_printf("|%s|\n", print_repeater(a,82));
  int page = 1;
  int pages = 0;
  int first_time = true;


  int total=0;
  RespCreated* resp_created;
  while(first_time || page<=pages){
    
    int ntoken = 9 + 13*20;
    jsmntok_t token[ntoken];
    jsmn_parser parser;
    jsmn_init(&parser);

    char parms[5];
    parms[0] = '/';
    sprintf(parms+1, "%d", page);

    if(!send_g(f_created,f_server_config._api_key,parms,data_callback))
      return;
    
    if (!response){
      printf("created: error receiving response from server!\n");
      break;
    }
    int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
    
    if (token[0].type != JSMN_OBJECT){
      printf("created: error parsing response from server!\n");
      free(response);
      response = NULL;
      break;
    }

    resp_created = dump_created(response,token);
      
    if (resp_created == NULL){
      printf("created: malformed page!\n");
      free(response);
      response = NULL;
      break;
    }

    if(first_time)
      pages = resp_created->pages;

    if(resp_created->metadata && resp_created->size){
      for (int i = 0; i < resp_created->size; ++i){
        r_cons_printf("| %-25s | %-4.4d | %-45.45s | %-60.60s | %-80.80s |\n",(resp_created->metadata+i)->id,(resp_created->metadata+i)->rank,(resp_created->metadata+i)->name,(resp_created->metadata+i)->prototype,(resp_created->metadata+i)->comment);
        free((resp_created->metadata+i)->name);
        free((resp_created->metadata+i)->prototype);
        free((resp_created->metadata+i)->comment);
        free((resp_created->metadata+i)->id);
        total++;
      }
      free(resp_created->metadata);
      resp_created->size = 0;

    }
    free(resp_created); 
    resp_created = NULL;      
    page++;
    if (first_time)
      first_time =false;
    
    free(response);
    response = NULL;


  }
  r_cons_printf("\nTotal = %d\n", total);
}




void do_apply(RCore* core,const char* id, int addr){
  char* mid[1];
  mid[0] = id;
  MetadataServer m;
  s_get(mid,NULL,1,&m);
  if (m.comment || m.name || m.prototype){

    char cmd[100];
    if (m.comment){
      sprintf(cmd, "CCu %.80s @ 0x%08x", m.comment, addr); 
      r_core_cmd0(core, cmd);
      free(m.comment);
    }
    
    if (m.name){
      sprintf(cmd, "afn %.80s @ 0x%08x\0", m.name, addr); 
      r_core_cmd0(core, cmd);
      free(m.name);

    }

    if (m.prototype){
      printf("%s\n", m.prototype);
      sprintf(cmd, "CC+ \\n prototype = %.80s @ 0x%08x", m.prototype, addr); 
      r_core_cmd0(core, cmd);
      free(m.prototype);
    }

    s_applied(id);

    delete_db(addr);
    
    DBdata d;
    strncpy(d.id, id,25);
    d.id[25]= '\0';
    d.address = addr;
    d.deleted = false;
    save(d);
    r_cons_printf("Annotations applied to function of address 0x%08x\n", addr);
  }


}


bool save(DBdata d){
  FILE* f;
  char db_path[strlen(getenv("HOME"))+strlen("/.config/first/db/.dat") + strlen(hashes.f_md5) + 1];
  strcpy(db_path,getenv("HOME"));
  strcat(db_path,"/.config/first/db/");
  strcat(db_path,hashes.f_md5);
  strcat(db_path,".dat");
  
  if(f = fopen(db_path,"r+")){
    
    int exist = exist_in_file(f,d);
    if( exist == -2){
      fclose(f);
      return true;
    }
    
    if (exist == -1)
      fseek(f, 0 , SEEK_END);
    
    if (exist >= 0)
     fseek(f, sizeof(DBdata) * exist , SEEK_SET);
    
    goto first_beach; 
    
  }

  if(f = fopen(db_path,"w+")){
    goto first_beach;
  }

  return false;

first_beach:
  fwrite(&d, sizeof(DBdata),1, f);
  fclose(f);
  return true;
}



int exist_in_file(FILE* f, DBdata d){
  if (!f)
    return false;

  DBdata c;
  int i = 0;
  int d_ind = -1;
  while (fread(&c, sizeof(DBdata),1,f) > 0){
    if(strcmp(c.id, d.id) == 0 && !c.deleted)
      return -2;
    if (c.deleted)
      d_ind = i;
    i++;
  }
  return d_ind;
}




char* delete_db(const int addr){
  FILE* f;
  char db_path[strlen(getenv("HOME"))+strlen("/.config/first/db/.dat") + strlen(hashes.f_md5) + 1];
  strcpy(db_path,getenv("HOME"));
  strcat(db_path,"/.config/first/db/");
  strcat(db_path,hashes.f_md5);
  strcat(db_path,".dat");
  
  f = fopen(db_path,"r+");
  if(!f)
    return NULL;


  DBdata c;
  while (fread(&c, sizeof(DBdata),1,f) > 0){
    if(c.address == addr){
      if(c.deleted){
        fclose(f);
        return NULL;
      }
      fseek(f, -sizeof(DBdata), SEEK_CUR);
      c.deleted = true;
      fwrite(&c, sizeof(DBdata), 1, f);
      fclose(f);
      char* id = strdup(c.id);
      return id;
    }
  }
  fclose(f);
  return NULL;
}







bool delete_db_unknown_file(const char id[]){

  char db_path[strlen(getenv("HOME"))+strlen("/.config/first/db/") + 1];
  strcpy(db_path,getenv("HOME"));
  strcat(db_path,"/.config/first/db/");

  FILE* f;
  DIR* dir;
  struct dirent *dptr = NULL;
  
  dir = opendir(db_path);
  if (!dir)
    return false;

  bool found = false;
  while(!found && (dptr = readdir(dir)) != NULL){

    if(!strcmp (dptr->d_name, "..") || !strcmp (dptr->d_name, "."))
        continue;
    char pth[strlen(db_path)+ strlen(hashes.f_md5) + 1];
    strcpy(pth,db_path);
    f = fopen(strcat(pth,dptr->d_name), "r+");
    
    if(!f)
      continue;

    DBdata c;
    while (!found ,fread(&c, sizeof(DBdata),1,f) > 0){
      
      if(strcmp(c.id, id) == 0 && !c.deleted){

        fseek(f, -sizeof(DBdata), SEEK_CUR);
        c.deleted = true;
        fwrite(&c, sizeof(DBdata), 1, f);
        found = true;
        break;
      }
    }
    fclose(f);

  }


  closedir(dir);
  if (found)
    return true;
  else
    return false;
}



char* check_db(const int addr){
  FILE* f;
  int address;
  char db_path[strlen(getenv("HOME"))+strlen("/.config/first/db/.dat") + strlen(hashes.f_md5) + 1];

  strcpy(db_path,getenv("HOME"));
  strcat(db_path,"/.config/first/db/");
  strcat(db_path,hashes.f_md5);
  strcat(db_path,".dat");
  
  f = fopen(db_path,"r");
  if(!f)
    return NULL;


  DBdata c;
  while (fread(&c, sizeof(DBdata),1,f) > 0){
    if(c.address == addr){
      if(c.deleted){
        fclose(f);
        return NULL;
      }
      char* id = strdup(c.id);
      return id;
    }
  }
  fclose(f);
  return NULL;
}







bool check_db_unknown_file(const char id[]){

  char db_path[strlen(getenv("HOME"))+strlen("/.config/first/db/") + 1];
  strcpy(db_path,getenv("HOME"));
  strcat(db_path,"/.config/first/db/");

  FILE* f;
  DIR* dir;
  struct dirent *dptr = NULL;
  
  dir = opendir(db_path);
  if (!dir)
    return false;

  bool found = false;
  while(!found && (dptr = readdir(dir)) != NULL){

    if(!strcmp (dptr->d_name, "..") || !strcmp (dptr->d_name, "."))
        continue;
    char pth[strlen(db_path)+ strlen(hashes.f_md5) + 1];
    strcpy(pth,db_path);
    f = fopen(strcat(pth,dptr->d_name), "r+");
    
    if(!f)
      continue;

    DBdata c;
    while (!found ,fread(&c, sizeof(DBdata),1,f) > 0){
      
      if(strcmp(c.id, id) == 0 && !c.deleted){
        found = true;
        break;
      }
    }
    fclose(f);

  }


  closedir(dir);
  if (found)
    return true;
  else
    return false;
}



// void read_db(){
//   FILE* f;
//   char id[26];
//   char db_path[strlen(getenv("HOME"))+strlen("/.config/first/db/.dat") + strlen(hashes.f_md5) + 1];
//   if (!db_path)
//     return;
//   strcpy(db_path,getenv("HOME"));
//   strcat(db_path,"/.config/first/db/");
//   strcat(db_path,hashes.f_md5);
//   strcat(db_path,".dat");

//   if( f = fopen(db_path,"r")){
//     DBdata c;
//     while (fread(&c, sizeof(DBdata),1,f) > 0){
//       printf("%s %d %d\n",c.id, c.address, c.deleted );
//     }
//     fclose(f);
//   }

// }

