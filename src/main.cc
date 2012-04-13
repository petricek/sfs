#include "sfs_secure.h"
#include "sfs_misc.h"
#include "sfs_lib.h"
#include "mrsa.h"
#include <stdio.h> 
#include <string.h> 

main()
{
  char * data = NULL, * encrypted = NULL;
  data = strdup("Venca je makac - uz prisel na to ze tudy cesta nevede a nakonec nasel cestu uplne jinou, kterou dosel na misto podobne tomu na nez chtel dojit :-)");
  printf("Data :          %s\n",data);

  rsa_key pub_key, priv_key;
  sfs_asym_generate_key(&pub_key, &priv_key);
  char * klic = sfs_asym_serialize_key(&pub_key);
  char s[NSIZE*4+2];
  // prints out the public key
  puts("Done, key components: pq,e,d,p,q,dp,dq,qp");
  printf("bits = %lu\n",pub_key.b);
  nh(s,pub_key.pq); puts(s);
  nh(s,pub_key.e); puts(s);
  nh(s,pub_key.d); puts(s);
  nh(s,pub_key.p); puts(s);
  nh(s,pub_key.q); puts(s);
  nh(s,pub_key.dp); puts(s);
  nh(s,pub_key.dq); puts(s);
  nh(s,pub_key.qp); puts(s);
  printf("Pub key: %s\n", klic);
  fflush(stdout);
  printf("bits: %lu\n", pub_key.b);


  printf("Data :          %s\n",data);
  int len = strlen(data);
  char * hex = NULL;
  hex = bit2hex(data,len);
  printf("Data in hex:    %s\n",hex);
  data = hex2bit(hex,0);
  printf("Data :          %s\n",data);
  len = strlen(data);

  int data_len = strlen(data);
  encrypted = sfs_asym_encrypt(&pub_key,data,data_len);
  
  printf("encrypted bin:\n");
  for(uint i=0;i<64;i++)
    printf("%d",encrypted[i]);
  printf("\n");
  
  hex = bit2hex(encrypted,len);
  printf("Hex encrypted : %s\n",hex);
  fflush(stdout);

  // em((N)encrypted,priv_key.d,priv_key.pq);

  char * decrypted = sfs_asym_decrypt(&priv_key,encrypted,data_len);

  printf("Decrypted     : %s\n",decrypted);
  hex = bit2hex(decrypted,32);
  printf("Hex decrypted : %s\n",hex);
  fflush(stdout);

}
