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
	bool has_changed; //True if function metadata has changed
	bool is_lib; //True if function is a library function
	bool created; //True if the annotations were created by user
	char* signature; //The opcodes associated with the function // String (base64 encoded)
	int apis_size;
	char** apis; //The APIs called by the function // List of Strings (max_string_length = 64)
	// not used
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
	char* engines;
	// not used yet
	
}MetadataServer;

typedef struct RespCreated
{
	int pages;
	MetadataServer* metadata;
	int size;

	
}RespCreated;


typedef struct DBdata
{
	char id[26];
	int address;
	bool deleted;
}DBdata;



// communication with server
bool send_g(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream));
bool send_p(action act, char* token, char* parms, size_t callback(void *ptr, size_t size, size_t nmemb, void *stream));
bool s_test_connection();
void s_check_in(action act);
bool s_add(Metadata metadata[], int size, char* arch);	
void s_history(char** metadata_id, int size);
void s_applied(char* metadata_id);
bool s_unapplied(char* metadata_id);
bool s_delete(const char* metadata_id);
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
char* get_prototype(RCore *core , RAnalFunction *fcn);
char* get_comment(RCore* core, RAnalFunction *fcn);
bool set_comment(RCore* core, RAnalFunction *fcn, const char* comment);
Metadata* get_fcns_db(int *i);







bool do_add(RCore *core,RAnalFunction *fcn);
bool do_add_all(RCore* core, RList* fcns, const char* comm);
bool populate_fcn(RCore* core);
void do_get();
void do_delete(RCore* core, const char id[]);






//DB
bool save(DBdata d);
int exist_in_file(FILE* f, DBdata d);
void read_db();
int delete_db(const char id[]);
#endif