# Verify Authenticode Digital Signature (C++)
**Verify executable's digital signature (internal and by catalogue), written in C++**

**Supports**
 - x64 and x32 applications (temporarily disable file redirector)
 - internal signature check
 - Microsoft catalogue check
 
**Does not support**
 - Driver WHQL check is not included

**Notice**
 - I don't see any reliable stand-alone code examples on C++ all over, so I re-wrote on C++ the analogue of my [VB6 implementation](https://github.com/dragokas/hijackthis/blob/devel/src/modVerifyDigiSign.bas#L1050) from HiJactkHis Fork project.
