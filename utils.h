#ifndef __UTILS__
#define __UTILS__



#include <stdbool.h>
#include <r_core.h>
#include <r_socket.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>


typedef enum action {
f_test,
f_checkin,
f_add,
f_history,
f_applied,
f_unapplied,
f_delete,
f_created,
f_get,
f_scan
} action;


typedef struct binary_info{
  char* f_md5;
  char* f_sha1;
  char* f_sha256;
  int f_crc32;

}binary_info;


typedef struct Config
{
	char* _server;
	uint _port;	
	char* _protocol;
    bool _verify;
    bool _auth;
    char* _api_key;
} FS_config;



typedef struct Metadata
{
	char* id; // The First ID assosciated with the function
	char* creator; //The handle of the annotation creator
	int address; //The virtual address associated with the function
	char* name; //The name of the function // String (max_length = 128)
	char* original_name; //The orginal name of the function
	char* prototype; //The prototype of the function // String (max_length = 256)
	char* comment; //The repeatable comment associated with the function // String (max_length = 512)
	int segment; //The start address of the function's segment
	int offset; //The function offset from the start of the segment
	bool created; //True if the annotations were created by user
	bool is_lib; //True if function is a library function
	bool has_changed; //True if function metadata has changed
	char* signature; //The opcodes associated with the function // String (base64 encoded)
	char* apis[]; //The APIs called by the function // List of Strings (max_string_length = 64)
}Metadata;

typedef struct MetadataServer
{
	int address; //The virtual address associated with the function
	char* name; //The name of the function
	char* prototype; //The prototype of the function
	char* comment; //The comment associated with the function
	char* creator; //The handle of the annotation creator
	char* id; //The FIRST ID associated with this metadata
	int rank; //The number of unqiue applies of this metadata
	float similarity; //The percentage of similarity between this function and the original queried for function. This value can be very rough estimate depending on the engine.
	// not used yet
	//char* engines;
	
}MetadataServer;

typedef struct RespCreated
{
	int pages;
	MetadataServer* metadata;
	int size;

	
}RespCreated;


// communication with server
void send_g(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream));
void send_p(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream));
bool s_test_connection();
void s_check_in(action act);
void s_add(Metadata metadata);
void s_history(char** metadata_id, int size);
bool s_applied(char* metadata_id);
bool s_unapplied(char* metadata_id);
bool s_delete(char* metadata_id);
void s_get(char** metadata_id, int size);
void s_scan(Metadata metadata);
RespCreated s_created();








// setter and getters
bool  f_set_config();
void set_token();
void set_hashes(RCore *core);
char* get_token();
char* get_arch(RCore* core);
char* get_signature(RCore* core, const RAnalFunction* fcn);
char** get_apis(RCore* core, RAnalFunction* fcn, int* size);

#endif