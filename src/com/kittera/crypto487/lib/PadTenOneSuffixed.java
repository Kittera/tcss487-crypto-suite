package com.kittera.crypto487.lib;

import com.kittera.crypto487.lib.interfaces.PaddingRule;

import java.util.Arrays;

public class PadTenOneSuffixed implements PaddingRule {
   
   private final byte mySuffix;
   
   protected PadTenOneSuffixed(byte suffix) {
      mySuffix = suffix;
   }
   /**
    * Applies pad10*1 rule while also appending given suffix byte.
    * @param in the input byte string to be padded with suffix
    * @return padded byte string
    */
   @Override
   public byte[] apply(byte[] in, int rateInBits) {
      return padSuffix0_1(in,rateInBits, mySuffix);
   }
   
   /**
    * Applies pad10*1 rule aka Multi-Rate Padding to the input bytestring with a
    * parameterized suffix byte for domain separation. Input byte array will be expanded
    * and modified to add padding. Accepts parameter for the specific delimiter byte.
    *
    * @param inBytes input byte array to be padded under pad10*1
    * @param bitRate the rate of absorption in bits per chunk, equal to b - c
    * @return modified byte array with added padding
    */
   protected byte[] padSuffix0_1(byte[] inBytes, int bitRate, byte suffix) {
      if (suffix == 0x00)
         throw new IllegalArgumentException(
               "Suffix cannot be all 0's!Must have as least one 1 bit."
         );
      
      int byteRate = bitRate / 8;
      int q = byteRate - (inBytes.length % byteRate);
      byte[] result = Arrays.copyOf(inBytes, inBytes.length + q);
   
      result[inBytes.length] = suffix; // first apply given suffix
      for (int i = inBytes.length + 1; i < result.length; i++)
            result[i] = (byte) 0;
      
      result[result.length - 1] ^= (byte) 0x80; //adds final 1 bit (in reversed byte form)
      return result;
   }
}
