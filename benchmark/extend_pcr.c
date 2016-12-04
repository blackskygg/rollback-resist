#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

int main(int argc, char *argv[])
{
  TPM_RC rc = 0;
  TSS_CONTEXT *tss_ctx = NULL;
  PCR_Extend_In in;
  char data[sizeof(TPMU_HA)];
  int n_loops, n_pcrs;
  struct timeval tm1, tm2;

  if (argc < 3) {
    puts("Usage: ./a.out n_loops n_pcrs");
    goto EXIT;
  }
  n_loops = strtod(argv[1], NULL);
  n_pcrs = strtod(argv[2], NULL);

  for (int i = 0; i < sizeof(TPMU_HA); ++i)
    data[i] = i % 256;

  //connect to server
  if (rc = TSS_Create(&tss_ctx)) goto EXIT;

  //setup the COMMAND_PARAMETERS
  in.digests.count = 1;
  in.digests.digests[0].hashAlg = TPM_ALG_SHA1;
  memset(&in.digests.digests[0].digest, 0, sizeof(TPMU_HA));

  // start to test
  gettimeofday(&tm1, NULL);
  for (int i = 0; i < n_loops; ++i) {
    for (int j = 0; j < n_pcrs; ++j) {
      in.pcrHandle = j;

      rc = TSS_Execute(tss_ctx,
		       NULL,
		       (COMMAND_PARAMETERS *)&in,
		       NULL,
		       TPM_CC_PCR_Extend,
		       TPM_RS_PW, NULL, 0,
		       TPM_RH_NULL, NULL, 0);
      if (rc) goto EXIT;
    }
  }
  gettimeofday(&tm2, NULL);

  //get difftime
  tm1.tv_sec = tm2.tv_sec - tm1.tv_sec;
  if ((tm1.tv_usec = tm2.tv_usec - tm1.tv_usec) < 0) {
    tm1.tv_sec--;
    tm1.tv_usec += 1e6;
  }
  
  printf("%ld ", tm1.tv_sec);
  printf("%ld\n", tm1.tv_usec);


 EXIT:
  if (tss_ctx != NULL) rc = TSS_Delete(tss_ctx);
  if (rc) puts("Error");
  return 0;
}
