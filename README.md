# VMHide
Bypasses VMProtect's VMWare &amp; VMWare Tools detection trough user-mode API hooks. Works for version 3.5 since they didn't use direct syscalls prior to version 3.6+

## Usage
- Add **hypervisor.cpuid.v0 = "FALSE"** in your .vmx file
- Inject the DLL at the same time the target process starts. I will attach an image below that shows the optimal settings for the [Xenos](https://github.com/DarthTon/Xenos) injector.

![image](https://github.com/user-attachments/assets/c2e29c2e-02e2-4ccf-8e5c-659920f9d967)

![image](https://github.com/user-attachments/assets/41477f0b-abce-4b02-ba35-1a230d243555)

# Before using VMHide
![image](https://github.com/user-attachments/assets/5ac70ef0-b0d2-4204-8699-802f49235954)

# After using VMHide
![image](https://github.com/user-attachments/assets/1e525ae3-fca2-43e4-970c-c656077ea32b)
