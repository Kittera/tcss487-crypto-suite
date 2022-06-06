package com.kittera.crypto487.lib.enums;


import com.kittera.crypto487.lib.interfaces.BitsAndBytes;

/**
 * Enumerator for easy access to established constants from the SHA-3 standard.
 */
public class SHA3Parameters {
   
   /**
    * For SHA3, b must be the maximum of 1600 as per FIPS 202. Determined by 25 * 2 ** l
    */
   public static final int KECCAK_STATE_SIZE_BITS = 1600;
   
   public static final int KECCAK_NUM_PERM_RNDS = 24;
   
   
   public enum SHA3 implements BitsAndBytes {
   
      SHA3_224(224, (byte) 0x06),
      SHA3_256(256, (byte) 0x06),
      SHA3_384(384, (byte) 0x06),
      SHA3_512(512, (byte) 0x06);
   
      /**
       * SHA3 requires that capacity be equal to twice the digest length.
       */
      public final int capacity;
   
      /**
       * SHA3 requires c = 2d, but r + c is b, the block size, and so r = b - c.
       */
      public final int rate;
   
      /**
       * Base parameter of SHA3 variants upon which almost all other parameters are based.
       */
      public final int digestLength;
   
      /**
       * SHA3 specifies a domain separator to be appended to all input messages depending on
       * the function being performed.
       */
      public final byte delimitedSuffix;
   
      SHA3(int dLen, byte suffix) {
         this.digestLength = dLen;
         this.capacity = (2 * dLen);
         this.rate = (KECCAK_STATE_SIZE_BITS - this.capacity);
         this.delimitedSuffix = suffix;
      }
   
      /**
       * Returns the digest size in bits.
       * @return bit length of digest
       */
      @Override
      public int inBits() {
         return digestLength;
      }
   
      /**
       * Returns the digest size in bytes.
       * @return byte length of digest
       */
      @Override
      public int inBytes() {
         return digestLength / 8;
      }
   }
   
   public enum SHAKE implements BitsAndBytes {
      SHAKE128(256, (byte) 0x1F),
      SHAKE256(512, (byte) 0x1F),
      cSHAKE128(256, (byte) 0x04),
      cSHAKE256(512, (byte) 0x04);
   
      /**
       * SHA3 requires that capacity be equal to twice the digest length.
       */
      public final int capacity;
   
      /**
       * SHA3 requires c = 2d, but r + c is b, the block size, and so r = b - c.
       */
      public final int rate;
   
      /**
       * SHA3 specifies a domain separator to be appended to all input messages depending on
       * the function being performed.
       */
      public final byte paddedSuffix;
      
      SHAKE(int spongeCapacity, byte suffix) {
         this.capacity = spongeCapacity;
         this.paddedSuffix = suffix;
         this.rate = (KECCAK_STATE_SIZE_BITS - this.capacity);
      }
   
      /**
       * @return the specified rate for a sponge implementing SHAKE, in bits
       */
      @Override
      public int inBits() {
         return rate;
      }
   
      /**
       * @return the specified rate for a sponge implementing SHAKE, in bytes
       */
      @Override
      public int inBytes() {
         return rate / 8;
      }
   }
}
