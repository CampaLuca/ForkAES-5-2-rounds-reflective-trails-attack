# ForkAES 5+2-2 rounds reflection trail attack

The repository contains both the attack against ForkAES-*-2-2 with 128 bits tweak, both the attack against ForkAES-*-2-2 with 64 bits tweak.

With respect to the attack with 64 bits tweak, the code will find only half of the bytes because the other ones need to be find by applying the techniques described in the draft.

### Utility

The utility.c code within the Utility folder was used during the analysis to perform the operations as AES does. 

### How to compile

```gcc attack.c -o attack -O1```

### Possible changes

In the file ```forkaes_configuration.h``` you can change the number of cores you want to use for multithreading operations and the number of rounds for each section.


