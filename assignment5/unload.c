#include <sys/klog.h>
#include <sys/syscall.h>

int main()
{
syscall(SYS_syslog, 42, 0xabad1dea, 1337);
delete_module("module_hiding", 0);
}
