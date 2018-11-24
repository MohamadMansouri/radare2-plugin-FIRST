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
char* response_get = NULL;
Metadata* pop_list = NULL;
int num_fcn = 0;

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
      fprintf(stderr, "failed to connect to server: %s\n",curl_easy_strerror(res));
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

  if (checkedin || act == f_test)
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
  if(!send_p(f_history, f_server_config._api_key, parms, data_callback))
    return;
  
  if (!response){
    printf("Error receiving response from server!\n");
    return NULL;
  }
  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  
  if (token[0].type != JSMN_OBJECT){
    printf("Error parsing response from server!\n");
    free(response);
    response = NULL;
    return NULL;
  }

// TODO: implement the parser of the histoy
  return NULL;

}

void s_get(char** metadata_id, int size){
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
  
  if (r != ntoken &&  token[0].type != JSMN_OBJECT){
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
      r_cons_printf("%-25.25s", id);
      jsmntok_t* tt = t+i+1;
      for(int j = 1 ; j < (tt->size)*2 ; j+=2){
        int width=0;
        if(!jsoneq(response, tt+j, "name") && (tt+j)->type == JSMN_STRING)
          width = 50;
        if(!jsoneq(response, tt+j, "prototype") && (tt+j)->type == JSMN_STRING)
          width = 50;
        if(!jsoneq(response, tt+j, "comment") && (tt+j)->type == JSMN_STRING)
          width = 50;
        if(!jsoneq(response, tt+j, "creator") && (tt+j)->type == JSMN_STRING)
          width = 20;
        if(!jsoneq(response, tt+j, "rank")&& (tt+j)->type == JSMN_STRING)
          width = 2;
        if(width)
          r_cons_printf("\t%-*.*s", width, ((tt+j+1)->end - (tt+j+1)->start) > width ? width : ((tt+j+1)->end - (tt+j+1)->start) ,response+(tt+j+1)->start );
      }    
      r_cons_printf("\n");
    }
  }
  free(response);
  response = NULL;

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
    if(!send_g(f_created,f_server_config._api_key,parms,data_callback))
      return metadata_array;

    
    if (!response){
      printf("Error receiving response from server!\n");
      break;
    }
    
    int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
    
    if (token[0].type != JSMN_OBJECT){
      printf("Error parsing response from server!\n");
      free(response);
      response = NULL;
      break;
    }

    resp_created = dump_created(response,token);
      
    if (resp_created == NULL){
      printf("Malformed response!\n");
      free(response);
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
    free(response);
    response = NULL;


  }
  return metadata_array;
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
    //   // printf("%d %d %s\n",as, strlen(at), at );
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
// printf("%s\n", parms);
free(parms);
if (!response){
  printf("add : error receiving response from server!\n");
  return false;
  }
  int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  if (r !=ntoken || token[0].type != JSMN_OBJECT){
    printf("add: error parsing response from server!\n");
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
        
        // printf("%d\n", t->size);
        // s_applied(id);

        DBdata d;
        strncpy(d.id, id,25);
        d.id[25]= '\0';
        d.address = addr_int;
        d.deleted = false;
        save(d);
        if (!pop_list)
          return false;

        int j,k;
        for (j=0; j< num_fcn; ++j){
          if((pop_list+j)->address == addr_int)
            break;
        }
        if(j == num_fcn)
          continue;

        for (k=0; k< size; ++k){
          if(metadata[k].address == addr_int)
            break;
        }
        if(k == size)
          continue;        

       if((pop_list + j)->name = malloc(strlen(metadata[k].name)+1))
          strcpy((pop_list + j)->name ,metadata[k].name);
       if((pop_list + j)->signature = malloc(strlen(metadata[k].signature)+1))
          strcpy((pop_list + j)->signature ,metadata[k].signature);
       if((pop_list + j)->comment = malloc(strlen(metadata[k].comment)+1))
          strcpy((pop_list + j)->comment ,metadata[k].comment);
       if((pop_list + j)->prototype = malloc(strlen(metadata[k].prototype)+1))
          strcpy((pop_list + j)->prototype ,metadata[k].prototype);
       if((pop_list + j)->id = malloc(strlen(id)+1))
          strcpy((pop_list + j)->id ,id);
        (pop_list + j)->offset = (pop_list + j)->address - (pop_list + j)->segment;
        (pop_list + j)->created = true;
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

void s_scan(Metadata metadata){
  
}

void s_applied(char* metadata_id){
  int ntoken = 5;
  jsmntok_t token[ntoken];
  jsmn_parser parser;
  jsmn_init(&parser);
  
  char parms[strlen("md5=&crc32=&id=") + strlen(hashes.f_md5) + strlen(metadata_id) + sizeof(hashes.f_crc32)];
  sprintf( parms,"md5=%s&crc32=%d&id=%s", hashes.f_md5, hashes.f_crc32,metadata_id);

  if(!send_p(f_applied,f_server_config._api_key, parms, data_callback))
    return;

  //   if (!response){
  //     printf("applied : error receiving response from server!\n");
  //     return false;
  //   }

  // int r = jsmn_parse(&parser, response, strlen(response), token, ntoken);
  // if (r !=ntoken || token[0].type != JSMN_OBJECT){
  //   printf("applied: error parsing response from server!\n");
  free(response);//   
  response = NULL;
  //   return false;
  // }
  // if(!jsoneq(response, &token[1], "failed") && token[2].type == JSMN_PRIMITIVE && *(response + token[2].start) == 'f' && !jsoneq(response, &token[3], "results")  && token[4].type == JSMN_PRIMITIVE && *(response + token[4].start) == 't'){
  //   free(response);
  response=NULL;
  //   return true;
  // }

  // return false;

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
  
  if (ini_parse(strcat(homedir,"/.config/first/first.config"), handler, &f_server_config) < 0) {
        printf("Can't load configuration file!\n");
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


Metadata* get_fcns_db(int *i){
  *i= num_fcn;
  return pop_list;
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


bool populate_fcn(RCore* core){
  
  if (pop_list)
    return true;

  RList* fcns = core->anal->fcns;
  pop_list = (Metadata*)malloc(sizeof(Metadata) * fcns->length);
  num_fcn = fcns->length;
  if(!num_fcn)
    return false;
  RListIter *iter;
  RAnalFunction *fcn;
  RBinSection* section;
  RBinObject* obj;
  obj = r_bin_cur_object(core->bin);
  int i = 0;
  r_list_foreach (fcns, iter, fcn) {
    (pop_list + i)->original_name = malloc(strlen(fcn->name) + 1);
    strcpy((pop_list + i)->original_name , fcn->name);
    (pop_list + i)->address = (int)fcn->addr;
    section = obj? r_bin_get_section_at (obj, fcn->addr, 1): NULL;
    (pop_list + i)->segment = section ? (int)section->vaddr : 0;
    i++;
  }
  return true;
}



void do_get(){
  FILE* f;
  char *path = NULL;
  int address;
  char id[26];
  path = (char*)malloc(strlen(getenv("HOME"))+strlen("/.config/first/.dat") + strlen(hashes.f_md5) + 1);
  if (!path)
    return;
  strcpy(path,getenv("HOME"));
  strcat(path,"/.config/first/");
  strcat(path,hashes.f_md5);
  strcat(path,".dat");

  if( f = fopen(path,"r")){
    int i = 0;
    char** mid = NULL;
    DBdata c;
    r_cons_printf("%-25s\t%-50s\t%-50s\t%-20s\t%-2s\t%-50s\n","ID","Comment","Name","Creator","Rank","Prototype");

    while (fread(&c, sizeof(DBdata),1,f) > 0 && !c.deleted){
      mid = (char**)realloc( mid ,sizeof(char*) * (i+1));
      *(mid + i) = malloc(strlen(c.id)+1);
      strcpy( *(mid + i), c.id);
      ++i;
    }
    fclose(f);
    int j = 0;
    while (i > 0){
      s_get(&mid[j], i > 19? 20 : i);
      j += 20;
      i -= 20;
    }

  }

}






void do_delete(RCore* core,const char id[]){
  if(s_delete(id)){
    int address = delete_db(id);
    if (address){
      RAnalFunction* fcn = r_anal_get_fcn_at(core->anal, (ut64)address,0);
      r_cons_printf("Annotations of function %s of address 0x%08x are deleted\n", fcn->name, fcn->addr);
    }
  }
  r_cons_printf("deletion failed\n");
}




bool save(DBdata d){
  FILE* f;
  char *path = NULL;
  int address;
  path = (char*)malloc(strlen(getenv("HOME"))+strlen("/.config/first/.dat") + strlen(hashes.f_md5) + 1);
  if (!path)
    return false;
  strcpy(path,getenv("HOME"));
  strcat(path,"/.config/first/");
  strcat(path,hashes.f_md5);
  strcat(path,".dat");
  

  if(f = fopen(path,"r+")){
    
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

  if(f = fopen(path,"w+")){
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
  printf("%d\n", d_ind);
  return d_ind;
}




int delete_db(const char id[]){
  FILE* f;
  char *path = NULL;
  int address;
  path = (char*)malloc(strlen(getenv("HOME"))+strlen("/.config/first/.dat") + strlen(hashes.f_md5) + 1);
  if (!path)
    return 0;
  strcpy(path,getenv("HOME"));
  strcat(path,"/.config/first/");
  strcat(path,hashes.f_md5);
  strcat(path,".dat");
  
  f = fopen(path,"r+");
  if(!f)
    return 0;


  DBdata c;
  while (fread(&c, sizeof(DBdata),1,f) > 0){
    if(strcmp(c.id, id) == 0){
      if(c.deleted){
        fclose(f);
        return c.address;
      }
      fseek(f, -sizeof(DBdata), SEEK_CUR);
      c.deleted = true;
      fwrite(&c, sizeof(DBdata), 1, f);
      fclose(f);
      return c.address;
    }
  }
  fclose(f);
  return 0;
}


void read_db(){
  FILE* f;
  char *path = NULL;
  int address;
  char id[26];
  path = (char*)malloc(strlen(getenv("HOME"))+strlen("/.config/first/.dat") + strlen(hashes.f_md5) + 1);
  if (!path)
    return;
  strcpy(path,getenv("HOME"));
  strcat(path,"/.config/first/");
  strcat(path,hashes.f_md5);
  strcat(path,".dat");

  if( f = fopen(path,"r")){
    DBdata c;
    while (fread(&c, sizeof(DBdata),1,f) > 0){
      printf("%s %d %d\n",c.id, c.address, c.deleted );
    }
    fclose(f);
  }

}