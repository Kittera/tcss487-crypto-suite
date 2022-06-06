package com.kittera.crypto487.util;

import java.util.Arrays;

/**
 * Provides several common array utilities.
 * @author Spencer Little
 * @version 1.0.0
 */
public class ArrayUtils {
   
   /**
    * Merges two bytes arrays. Places elements from b1 before b2 in the
    * new merges array.
    * @param b1 the first array to be merged
    * @param b2 the second array to be merged
    * @return a new array that has all elements of b1 and b2
    */
   public static byte[] mergeByteArrays(byte[] b1, byte[] b2) {
      byte[] mrg = Arrays.copyOf(b1, b1.length + b2.length);
      System.arraycopy(b2, 0, mrg, b1.length, b2.length);
      return mrg;
   }
   
   public static byte[] byteArrayXOR(byte[] b1, byte[] b2) {
      if (b1.length != b2.length) {
         throw new IllegalArgumentException("Can only byte-array-XOR on arrays of the same size.");
      }
      
      byte[] b3 = new byte[b1.length];
      int count = 0;
      while (count < b1.length) {
         b3[count] = (byte) (b1[count] ^ b2[count++]);
      }
      return b3;
   }
   
   public static boolean byteArrayEquals(byte[] b1, byte[] b2) {
      if (b1.length != b2.length) {
         throw new IllegalArgumentException("Can only byte-array-XOR on arrays of the same size.");
      }
      
      boolean result = true;
      int count = 0;
   
      while (count < b1.length) {
         if (b1[count] != b2[count++]) {
            result = false;
            break;
         }
      }
      
      return result;
   }
}
