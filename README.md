[NOT WORKING ANYMORE] HollowProcess
=============

Hollow Process / Dynamic Forking / RunPE injection technique implemented in Python 2.


A simple implementation of the well known Process Hollowing technique used by malware.
The idea to create this came from the excellent book Practical malware analysis.

Warning: This is not 100% stable and reliable. Although I have had a 100% success rate on svchost.exe with a 32 bit payload.




If the payload is an protected executable it will create 0xC0000005 error (Access Violation).


Dependencies:

 - Pefile:
    install using: pip install pefile

