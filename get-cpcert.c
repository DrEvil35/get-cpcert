 
//#include "libcpcert.h" 
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "libcpcert.h"

#define OPTSTR "i:p:k:o:h"


extern int errno;
extern char *optarg;
extern int opterr, optind;

typedef struct {
	FILE* output;
	const char* zip_password;
	const char* pincode;
	const char* input;
} options_t;

int is_file(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

int dir_exists(const char *path)
{
    struct stat info;

    if(stat( path, &info ) != 0)
        return 0;
    else if(info.st_mode & S_IFDIR)
        return 1;
    else
        return 0;
}




int main(int argc, char *argv[]){
	int opt;
	options_t options = { stdout , "", "" , "" };
	container_t container;
	memset(&container,0,sizeof(container));
	
	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch(opt){
			case('o'):
				if (!(options.output = fopen(optarg, "w")) ){
					fprintf(stderr, "Unable to open out file");
					exit(EXIT_FAILURE);
				} 
				break;
			case('p'):
				options.zip_password = optarg;
				break;
			case('k'):
				options.pincode = optarg;
				break;
			case('i'):
				options.input = optarg;
				break;
			case('h'):
			default:
				fprintf(stderr, "Usage: [-i input zip/dir container] [-p zip password] [-k container key] [-o output file]\n" );
				exit(EXIT_FAILURE);
				
		}
	}
	if(dir_exists(options.input)){
		container_dir_files(options.input, &container);
	}
	else if(is_file(options.input)){
		if(container_zip_file(options.input, options.zip_password, &container)){
			exit(EXIT_FAILURE);
		}
// 		char* buf;
// 		int s = read_file(options.input,&buf);
// 		if(container_zip_memory(buf,s,options.zip_password, &container)){
// 			exit(EXIT_FAILURE);
// 		}
	} 
	else{
		printf("Input subject <%s> does not exists\n",options.input);
		exit(EXIT_FAILURE);
	}
	BIO* bio = BIO_new_fp(options.output, BIO_NOCLOSE|BIO_FP_TEXT);
	process_decode_container(&container,options.pincode, bio);
	BIO_free(bio);
	free_container(&container);
}
