package com.kittera.crypto487.lib;

public class Crypto487HashLib {
   
   /**
    * Enumerator for easy access to established constants from the SHA-3 standard.
    */
   public enum SHA3Parameters {
      
      SHA3_224((short) (2 * 224)),
      SHA3_256((short) (2 * 256)),
      SHA3_384((short) (2 * 384)),
      SHA3_512((short) (2 * 512));
      
      /**
       * For SHA3, b must be the maximum of 1600 as per FIPS 202.
       */
      public static final short SHA3_BLOCK_SIZE_BITS = 1600;
      
      /**
       * SHA3 requires that capacity
       */
      public final short capacity;
      
      /**
       *
       */
      public final short rate;
      
      SHA3Parameters(short capacity) {
         this.capacity = capacity;
         this.rate = (short) (SHA3_BLOCK_SIZE_BITS - this.capacity);
      }
   }
   
   /**
    * TODO
    */
   protected class KeccakCore {
      
      /**
       * Enumeration of the seven defined keccak-f permutations.
       */
      public enum KBlockSize {
         ERROR(-1),
         KECCAK_25(0),
         KECCAK_50(1),
         KECCAK_100(2),
         KECCAK_200(3),
         KECCAK_400(4),
         KECCAK_800(5),
         KECCAK_1600(6);
         
         /**
          * Keccak parameter b, total size of the state. Formula: 25 * 2 ** keccakL
          */
         private final short BLOCK_SIZE;
         
         /**
          * Keccak's parameter l, which determines various other parameters. Valid range:
          * [0, 6]
          */
         private final byte KECCAK_L;
         
         /**
          * Keccak parameter w, length of each of the 25 lanes in bits. Formula: 2 ** keccakL
          */
         private final byte LANE_WIDTH;
         
         /**
          * TODO
          *
          * @param kL Keccak parameter l, must be in the range [0, 6]
          */
         KBlockSize(final int kL) {
            assert (kL >= 0 && kL <= 6); //valid range for l
            
            this.KECCAK_L = (byte) kL;
            this.LANE_WIDTH = (byte) Math.pow(2, kL);
            this.BLOCK_SIZE = (short) (25 * this.LANE_WIDTH);
         }
         
         /**
          * Uses Keccak parameter B to select and initialize a new KeccakCore.
          *
          * @param candidateBlockSizeInBits Keccak parameter B, must be one of:
          *                                 25, 50, 100, 200, 400, 800, 1600
          * @return KBlockSize.ERROR by default, else corresponding enum constant
          */
         static KBlockSize findByB(final int candidateBlockSizeInBits) {
            KBlockSize result = ERROR;
            for (KBlockSize size : values()) {
               if (size.BLOCK_SIZE == candidateBlockSizeInBits) {
                  result = size;
                  break;
               }
            }
            return result;
         }
         
         /**
          * Uses Keccak parameter L to select and initialize a new KeccakCore.
          *
          * @param candidateL Keccak parameter L, must be one of:
          *                   0, 1, 2, 3, 4, 5, 6
          * @return KBlockSize.ERROR by default, else corresponding enum constant
          */
         static KBlockSize findByL(final int candidateL) {
            KBlockSize result = ERROR; //default value to prevent invalid state
            for (KBlockSize size : values()) {
               if (size.KECCAK_L == candidateL) {
                  result = size; // if match, test is successful.
                  break;
               }
            }
            return result;
         }
         
         /**
          * Accessor for block size in <b>bits</b>, which is Keccak's b parameter.
          *
          * @return ERROR if not properly selected, else BLOCK_SIZE
          */
         public int inBits() {
            assert this != ERROR;
            return this.BLOCK_SIZE;
         }
         
         /**
          * Accessor for block size in <b>bytes</b>, which is Keccak's b parameter
          * divided by eight.
          *
          * @return -1 if not properly selected, else BLOCK_SIZE / 8
          */
         public int inBytes() {
            assert this != ERROR;
            return this.BLOCK_SIZE / 8;
         }
         
         /**
          * Accessor for L parameter.
          * @return Keccak L parameter in range [0, 6] or IllegalStateException
          */
         public short correspondingL() {
            return this.KECCAK_L;
         }
         
      }
      
      /**
       * Keccak parameter r = b - c. Refers to those bits of the state which become
       * output.
       */
      private final short RATE;
      
      /**
       * Keccak parameter c = b - r. Refers to the "filler bits" in the rest of the state
       * array, which will not ultimately become hash output.
       */
      private final short CAPACITY;
      
      /**
       * Number of rounds for the round function of Keccak. Formula for number of rounds
       * is 12 + 2l, where l is an integer in the range [0, 6]. SHA3 <b>always</b> uses
       * the maximum for l, l=6, therefore for all SHA3-compliant KeccakCores,
       * NUM_ROUNDS = 24.
       */
      private final byte NUM_ROUNDS;
      
      /**
       * Block size parameter validation enum.
       */
      public final KBlockSize BLOCK_SIZE;
      
      
      /**
       * Default constructor, uses SHA3-256 required configuration:
       * b = 1600, c = 512, r = 1088).
       */
      protected KeccakCore() {
         this(KBlockSize.KECCAK_1600, SHA3Parameters.SHA3_256.capacity);
      }
      
      
      /**
       * Main constructor. Not for direct use.
       *
       * @param kBlockSize block size object used for configuration
       * @param kCapacity  parameter used to configure
       */
      private KeccakCore(final KBlockSize kBlockSize, final int kCapacity) {
         this.BLOCK_SIZE = kBlockSize;
         this.NUM_ROUNDS = (byte) (12 + (2 * this.BLOCK_SIZE.KECCAK_L));
         this.CAPACITY = (short) kCapacity;
         this.RATE = (short) (this.BLOCK_SIZE.inBits() - this.CAPACITY);
      }
      
      /**
       * Method which may be used to obtain a customized KeccakCore.
       *
       * @param parameterB Total state/block size in bits, Keccak's parameter b. Must be
       *                   one of: 25, 50, 100, 200, 400, 800, 1600
       * @param capacity   integer in range (1, b - 1)
       * @return appropriately initialized KeccakCore
       */
      protected KeccakCore fromBlockSize(final int parameterB, final int capacity) {
         //validate input, more sanity checking
         final KBlockSize candidateBlockSize = KBlockSize.findByB(parameterB);
         if (candidateBlockSize == KBlockSize.ERROR) {
            final String errstring = String.format("ParameterB given: %d", parameterB) +
                  """
                        Keccak block sizes are determined by 25 * (2 ** l), where l is in
                        range [0, 6]. Valid block sizes (b) are:
                        25, 50, 100, 200, 400, 800, 1600.
                        """;
            throw new IllegalArgumentException(errstring);
         }
         assert capacity < candidateBlockSize.inBits() - 1 && capacity > 1;
         
         //if we make it here, check succeeded and no exception was thrown
         return new KeccakCore(candidateBlockSize, capacity);
      }
      
      /**
       * Method used to start up a KeccakCore by specifying the l parameter.
       * @param parameterL L parameter of Keccak, valid range:  [0, 6]
       * @param parameterC C parameter of Keccak, capacity; 1 < C < 1600
       * @return appropriately initialized KeccakCore
       */
      protected KeccakCore fromL(final int parameterL, final int parameterC) {
         //validate input
         final KBlockSize candidateBlockSize = KBlockSize.findByL(parameterL);
         assert candidateBlockSize != KBlockSize.ERROR;
         
         //if we make it here, check succeeded and no exception was thrown
         return new KeccakCore(candidateBlockSize, parameterC);
      }
      
   }
}
