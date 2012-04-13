#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdio.h>


#define MAX_R 100
#define REA_R 20

#define WRITE

int
main()
{
  char buf[MAX_R] = "";
  int fd_in;
#ifdef WRITE
  int fd_out;
#endif
  
//  sleep( 20 );
  fd_in = open( "test.input", O_RDONLY );

  if (fd_in == -1) {
    perror( "open" );
    return 1;
  }

  printf( "... opened\n" ); 

  lseek( fd_in, 1, SEEK_CUR );
  read( fd_in, buf, REA_R );
  buf[REA_R] = 0;
  printf( "... read:\n%s\n", buf );
 
  close( fd_in );
  printf( "... closed\n" );

#ifdef WRITE
  fd_out = open( "test.output", O_RDWR|O_APPEND );

  if (fd_out == -1) {
    perror( "open" );
    return 1;
  }

  printf( "... opened\n" ); 

  printf( "... writing:\n%s\n", buf );
  write( fd_out, buf, REA_R );
  printf( "... written:\n%s\n", buf );
 
  close( fd_out );
  printf( "... closed\n" );
#endif

  close( 1 );
 
  return 0;
}
