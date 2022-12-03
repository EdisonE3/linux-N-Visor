#include <linux/kvm_host.h>

u64 rmi_version(){
    return 100;
}

u64 rmi_granule_delegate(u64 addr){
    return 0;
}

