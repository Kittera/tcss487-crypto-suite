package com.kittera.crypto487.lib;

import com.kittera.crypto487.lib.enums.KeccakBlockSize;
import com.kittera.crypto487.lib.interfaces.CryptographicDuplexSponge;
import com.kittera.crypto487.lib.interfaces.PaddingRule;
import com.kittera.crypto487.lib.interfaces.PermutationFunction;

import java.util.Arrays;

public class KeccakSponge implements CryptographicDuplexSponge {
   
   /**
    * Each sponge will absorb or squeeze a certain number of bits between applications
    * of the permutation function.
    */
   private final int bitRate;
   
   /**
    * Equals bitRate / 8. Stored as a pre-computation.
    */
   private final int byteRate;
   
   /**
    * PaddingRule objects have a built in function that pads byte arrays according to a
    * certain rule. This function is pad10*1 with provision for suffixes when implementing
    * SHA-3.
    */
   
   private final PaddingRule myPaddingRule;
   /**
    * Every Crypto Sponge has a permutation function to be applied between absorption
    * and squeezing of blocks.
    */
   
   private final PermutationFunction myPermutation;
   /**
    * State of the sponge represented in bytes.
    */
   private byte[] myState;
   
   /**
    * Constructor for simply making a sponge with no arbitrary starting state. Allocates
    * a 1600-bit array full of zeros.
    *
    * @param permuteFunc permutation function to be used in this sponge
    */
   public KeccakSponge(final PermutationFunction permuteFunc,
                       final PaddingRule paddingRule,
                       final KeccakBlockSize blockSize,
                       final int capacity
   ) {
      if (blockSize == KeccakBlockSize.ERROR) {
         throw new IllegalArgumentException(
               "KeccakSponge constructor received a KeccakBlockSize.ERROR"
         );
      }
      
      myPermutation = permuteFunc;
      myState = new byte[blockSize.inBytes()];
      myPaddingRule = paddingRule;
      bitRate = blockSize.inBits() - capacity;
      byteRate = bitRate / 8;
      
      init(); // ensure state is all zeroes
      // TODO Opportunity for integrity checking here if there's time
   }
   
   public void absorb(byte[] block) {
      int index = 0;
      for (byte byte_i : block) { // perform xor byte-by-byte to absorb
         myState[index++] ^= byte_i;
      }
      myState = myPermutation.apply(myState);
   }
   
   /**
    * Given an input message as a byte array, internally pad the message and then
    * absorb it into the sponge r bits at a time.
    *
    * @param x input message/data
    */
   @Override
   public void absorbAll(byte[] x) {
      byte[][] inputChunks = divideInput(myPaddingRule.apply(x, bitRate));
      for (byte[] inputChunk : inputChunks) {
         absorb(inputChunk);
      }
   }
   
   /**
    * Implements duplexed sponge functionality. Given an input block, pad if needed, then
    * absorb and permute, then return new state bits
    *
    * @param block input message/data
    * @return r bits from permuted state, may be ignored
    */
   @Override
   public byte[] duplexAbsorb(final byte[] block) {
      byte[] result = new byte[byteRate];
      
      if (block != null) { // if not null, we're absorbing
         if (block.length % byteRate != 0) {
            absorbAll(block);
         } else if (block.length != 0) {
            absorb(block);
         }
         System.arraycopy(myState, 0, result, 0, byteRate);
      } else {
         System.arraycopy(squeeze(), 0, result, 0, byteRate);
      }
      return result;
   }
   
   /**
    * After absorption, switch phases to squeezing.
    *
    * @return r bits from permuted state
    */
   @Override
   public byte[] squeeze() {
      byte[] result = new byte[byteRate];
      System.arraycopy(myState, 0, result, 0, byteRate);
      myState = myPermutation.apply(myState);
      return result;
   }
   
   /**
    * Splits one-dimensional input byte array into a two-dimensional array of r-bit chunks
    * for hashing.
    *
    * @param inBytes padded input byte array
    * @return array of (r/8)-byte arrays
    */
   private byte[][] divideInput(byte[] inBytes) {
      
      if (inBytes.length % byteRate != 0) {
         throw new IllegalArgumentException(
               "Input was not padded to a multiple of (r / 8) bytes"
         );
      }
      
      int blocksNeeded = inBytes.length / byteRate;
      byte[][] result = new byte[blocksNeeded][byteRate];
      
      int blockOffset = 0; // indexes into first dimension of result[][]
      while (blockOffset < blocksNeeded) {
         System.arraycopy(
               inBytes, (byteRate * blockOffset),
               result[blockOffset++], 0, byteRate);
      }
      
      return result;
   }
   
   /**
    * Fills state with zeros.
    */
   private void init() {
      Arrays.fill(myState, (byte) 0);
   }
   
}
