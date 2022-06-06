package com.kittera.crypto487.lib.enums;

/**
 * Enumeration of the seven defined keccak-f permutations.
 */
public enum KeccakBlockSize {
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
   private final int BLOCK_SIZE;
   
   /**
    * Keccak's parameter l, which determines various other parameters. Valid range:
    * [0, 6]
    */
   private final int KECCAK_L;
   
   /**
    * Keccak parameter w, length of each of the 25 lanes in bits. Formula: 2 ** keccakL
    */
   private final int LANE_WIDTH;
   
   
   /**
    * TODO
    *
    * @param kL Keccak parameter l, must be in the range [0, 6]
    */
   KeccakBlockSize(final int kL) {
//      assert (kL >= 0 && kL <= 6); //valid range for l
      
      this.KECCAK_L = kL;
      this.LANE_WIDTH = (int) Math.pow(2, kL);
      this.BLOCK_SIZE = (25 * this.LANE_WIDTH);
   }
   
   /**
    * Uses Keccak parameter B to select and initialize a new KeccakCore.
    *
    * @param candidateBlockSizeInBits Keccak parameter B, must be one of:
    *                                 25, 50, 100, 200, 400, 800, 1600
    * @return KBlockSize.ERROR by default, else corresponding enum constant
    */
   public static KeccakBlockSize findByB(final int candidateBlockSizeInBits) {
      KeccakBlockSize result = ERROR;
      for (KeccakBlockSize size : values()) {
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
   static KeccakBlockSize findByL(final int candidateL) {
      KeccakBlockSize result = ERROR; //default value to prevent invalid state
      for (KeccakBlockSize size : values()) {
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
   public int correspondingL() {
      return this.KECCAK_L;
   }
   
   public int laneWidth() {
      return this.LANE_WIDTH;
   }
   
}
