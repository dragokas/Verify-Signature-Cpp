# Verify Authenticode Digital Signature (C++)
**Verify executable's digital signature (internal and by catalogue), written in C++**

**Supports**
 - x64 and x32 applications (temporarily disable file redirector)
 - internal signature check
 - Microsoft catalogue check
 - SHA1 and SHA256 signature hashes (note: XP/Vista cannot check SHA256)
 - OS Windows XP/Vista/7/8/8.1/10/11 x32, x64
 
**Does not support**
 - Driver WHQL check is not included

**Requirements**
 - [Compatibility manifest](https://learn.microsoft.com/en-us/windows/win32/sysinfo/targeting-your-application-at-windows-8-1)

**Notice**
 - I don't see any reliable stand-alone code examples on C++ all over, so I re-wrote on C++ the analogue of my [VB6 implementation](https://github.com/dragokas/hijackthis/blob/devel/src/modVerifyDigiSign.bas#L1050) from HiJactkHis Fork project.

**Manual**
 - If you'd like detailed description of signature machanism, read [my article](https://www.cyberforum.ru/visual-basic/thread1978422.html) (on Russian).
