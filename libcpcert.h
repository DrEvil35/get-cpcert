#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <zip.h>
#include <stddef.h>
#include <gost_lcl.h>
#include <gosthash2012.h>
#include <libgen.h>

#define dllimport extern __attribute__((stdcall visibility("default"))

#define MAX_KEY_SIZE 64

#ifndef CPCERT_HEADER
#define CPCERT_HEADER


typedef struct {
  int alg, 
		parts, 
		cert_len, 
		key_size, 
		ecparam_id;
  unsigned char mask[MAX_KEY_SIZE], 
				prim[MAX_KEY_SIZE], 
				priv[MAX_KEY_SIZE],
				pub8[8], 
				salt[12],
				*cert;
  const char *password;
  void *trace_ctx;
  void (*trace)(void *ctx,const char* fmt,...);
} my_data_t;

typedef struct {
  unsigned char* data;
  long size;
  long limit;
  long pos;
  long ovf;
} packet_t;

typedef struct {
	packet_t header;
	packet_t masks;
	packet_t primary;
} container_t;

// external call dlopen
dllimport int unpack_zip_stream_container(const char* in_buf, uint64_t in_size, char** out_buf, uint64_t* out_size, const char* zip_passw, const char* secret);

dllimport container_zip_memory(const char* buf, uint64_t size, const char* zip_passw, container_t** container_array, size_t* size_container);
dllimport int container_zip_file(const char* file_name, const char* zip_passw, container_t* container);
dllimport void free_container(container_t* container);
dllimport int read_zip_containers_array(zip_t* zip, container_t** container_array, size_t* size_continer);
dllimport int process_decode_container(container_t* container, const char* passw, BIO* bio);
dllimport int parse_container_buffer(my_data_t* data, container_t* container);
dllimport int container_dir_files(const char* dir,container_t* container);
dllimport long read_file(const char* fn,char** buffer);
dllimport void free_heap(void* ptr);
dllimport void free_container_array(container_t* ptr, size_t size);


#endif
