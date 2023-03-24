#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>

uint8_t multiply(uint8_t  a, uint8_t  b) {
	uint8_t c = 0;
	while (a && b) {
		if (b & 1)		c ^= a; //if b is odd, then add to c
		if (a & 0x80)	a = (a << 1) ^ 0x11b; // XOR with the AES Rijndael primitive polynomial x^8 + x^4 + x^3 + x + 1
		else			a <<= 1;	// equivalent to a*2
		b >>= 1;
	}
	return c;
}

uint8_t inverse(uint8_t a) {
   for (int i = 0; i < 256; i++) {
      uint8_t operand = (uint8_t)i;
      if (multiply(a, operand) == 1) {
         return operand;
      }
   }

   return 0;
}


int main(int argc, char** argv) {
   

   int val;

   while (1) {
      printf("Usage:\n\t0: given A and B it will return the value X such that A * X = B\n\t1: given A and B, it will return X such that A * B = X\n\t2: given A, it will return the inverse X of A such that A * X = 1\n\n");
      scanf("%d", &val);


      if (val == 0) {
         int target;
         int start;
         printf("Start:");
         scanf("%d", &start);
         printf("\nTarget:");
         scanf("%d", &target);
         for (int i = 0; i < 256; i++) {
            uint8_t v = (uint8_t)i;

            if (multiply(start, v) == target) {
               printf("%d x %d = %d\n", start, v, target);
            }
         }

      } else if (val == 1) {
         int v1;
         int v2;
         
         printf("Value 1:");
         scanf("%d", &v1);
         printf("Value:");
         scanf("%d", &v2);

         printf("\nResult: %d x %d = %d\n", v1, v2, multiply((uint8_t)v1, (uint8_t)v2));

         
      } else if (val == 2) {
         printf("Inverse of: ");
         int v1;
         scanf("%d", &v1);

         printf("\nInverse: %d x %d = 1\n", v1, inverse((uint8_t)v1));


      }    

   }

}