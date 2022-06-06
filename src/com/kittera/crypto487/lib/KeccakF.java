package com.kittera.crypto487.lib;

import com.kittera.crypto487.lib.enums.KeccakBlockSize;
import com.kittera.crypto487.lib.interfaces.PermutationFunction;


public class KeccakF implements PermutationFunction {
   
   /**
    * Constants added to the first lane of the state during each round of the
    * permutation function.
    */
   private static final long[] roundConstants = {
         0x0000000000000001L,
         0x0000000000008082L,
         0x800000000000808AL,
         0x8000000080008000L,
         0x000000000000808BL,
         0x0000000080000001L,
         0x8000000080008081L,
         0x8000000000008009L,
         0x000000000000008AL,
         0x0000000000000088L,
         0x0000000080008009L,
         0x000000008000000AL,
         0x000000008000808BL,
         0x800000000000008BL,
         0x8000000000008089L,
         0x8000000000008003L,
         0x8000000000008002L,
         0x8000000000000080L,
         0x000000000000800AL,
         0x800000008000000AL,
         0x8000000080008081L,
         0x8000000000008080L,
         0x0000000080000001L,
         0x8000000080008008L
   };
   
   /**
    * Constants used in rotation of values within lanes.
    */
   private static final int[][] rhotationOffsetBases = {
         {0, 36, 3, 105, 210},
         {1, 300, 10, 45, 66},
         {190, 6, 171, 15, 253},
         {28, 55, 153, 21, 120},
         {91, 276, 231, 136, 78}
   };
   
   private final int myNumRounds;
   private final KeccakBlockSize myBlockSize;
   
   public KeccakF(final int numPermutationRounds, final KeccakBlockSize blockSize) {
      myNumRounds = numPermutationRounds;
      myBlockSize = blockSize;
   }
   
   /**
    * Applies permutation function a given number of times. For Keccak, this is determined
    * by the formula 12 + 2l where l is in the range [0, 6].
    *
    * @param inputState input byte array S to be permuted
    * @return new state S' as byte array
    */
   @Override
   public byte[] apply(byte[] inputState) {
      long[][] sPrime = bytesToLanes(inputState);
      for (int round = 0; round < myNumRounds; round++) {
         sPrime = iota(chi(pi(rho(theta(sPrime)))), round);
      }
      return lanesToBytes(sPrime);
   }
   
   /**
    * Method for left-rotating a laneWidth-bit value val to the left by offset given in
    * bits.
    * Inspired by C and Python implementations of FIPS 202 from the eXtended Keccak Code
    * Package, XKCP.
    *
    * @param val    laneWidth-bit value to be left-rotated (cyclically shifted)
    * @param offset number of bit positions by which to rotate
    * @return rotated value
    */
   protected static long rotNBitsLeft(long val, long offset, long laneWidth) {
      if (offset == 0) return val;
      return (
            ((val) << (offset % laneWidth)) ^ ((val) >>> ((laneWidth - offset) % laneWidth))
      );
   }
   
   /**
    * Analog of AES "ShiftRows" layer.
    *
    * @param state input state S as byte array
    * @return new state S' as byte array
    */
   private long[][] theta(long[][] state) {
      long[] columnParities = new long[5];
      for (int x = 0; x < 5; x++) {
         columnParities[x] =
               state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
      }
      
      long[][] sPrime = new long[5][5];
      for (int x = 0; x < 5; x++) { // for each sheet
         long parityWord = columnParities[(x + 1) % 5];
         long rotatedParityWord =
               rotNBitsLeft(parityWord, 1, myBlockSize.laneWidth());
         for (int y = 0; y < 5; y++) { // for each plane
            sPrime[x][y] =
                  state[x][y] ^ columnParities[(x + 4) % 5] ^ rotatedParityWord;
         }
      }
      return sPrime;
   }
   
   /**
    * Along with Pi, analog of AES "MixColumns" layer. Applies state bit rotations lane
    * by lane.
    *
    * @param state input state S as byte array
    * @return new state S' as byte array
    */
   private long[][] rho(long[][] state) {
      long[][] sPrime = new long[5][5];
      
      for (int x = 0; x < 5; x++) {
         for (int y = 0; y < 5; y++) {
            sPrime[x][y] = rotNBitsLeft(
                  state[x][y], rhotationOffsetBases[x][y], myBlockSize.laneWidth()
            );
         }
      }
      return sPrime;
   }
   
   /**
    * Along with Rho, analog of AES "MixColumns" layer. Applies state bit rotations plane
    * by plane.
    *
    * @param state input state S as byte array
    * @return new state S' as byte array
    */
   private long[][] pi(long[][] state) {
      long[][] sPrime = new long[5][5];
      
      for (int x = 0; x < 5; x++) {
         for (int y = 0; y < 5; y++) {
            sPrime[x][y] = state[((x + (3 * y)) % 5)][x];
         }
      }
      return sPrime;
   }
   
   /**
    * Analog of AES "SubBytes" layer. Introduces non-linearity by altering state bits
    * depending on certain other state bits. Specified in FIPS 202. Adapted from KXCP
    * reference C implementation.
    *
    * @param state input state S as byte array
    * @return new state S' as byte array
    */
   private long[][] chi(long[][] state) {
      // Step 1 of FIPS 202 Algorithm 4
      long[][] sPrime = new long[5][5];
      long[] temp = new long[5];
      for (int y = 0; y < 5; y++) { // for each lane in this sheet
         
         for (int x = 0; x < 5; x++) { // gather temporary snapshots of rows
            temp[x] = state[x][y];
         }
         
         for (int x = 0; x < 5; x++) { // perform substitution
            sPrime[x][y] = temp[x] ^ (~(temp[(x + 1) % 5]) & temp[(x + 2) % 5]);
         }
      }
      return sPrime;
   }
   
   /**
    * Analog of AES "AddRoundSubKey" layer. Uses round constants to modify state.
    *
    * @param state input state S as byte array
    * @param round which round the function is being applied in
    */
   private long[][] iota(long[][] state, int round) {
      state[0][0] ^= roundConstants[round];
      return state;
   }
   
   /**
    * Translates a one-dimensional byte array into a two-dimensional state array. The
    * state array is a 5x5 grid of longs for l=6 -> b = 1600.
    *
    * @param bytes bytes to group into lanes
    * @return matrix of longs for state representation and manipulation
    */
   protected long[][] bytesToLanes(byte[] bytes) {
      long[][] result = new long[5][5];
      int byteArrayIndexBase;
      
      for (int y = 0; y < 5; y++) {
         for (int x = 0; x < 5; x++) {
            long lane = 0;
            byteArrayIndexBase = ((5 * y) + x);
            
            for (int i = 0; i < 8; i++) { // byte concatenation happens here
               lane +=
                     (((long) bytes[byteArrayIndexBase * 8 + i]) & 0xff)
                           << (64 - (8 * (i + 1)));
            }
            result[x][y] = Long.reverseBytes(lane);
         }
      }
      return result;
   }
   
   /**
    * Translates two-dimensional state arrays, 5x5 arrays of longs, into a byte array for
    * output.
    *
    * @param lanes state array with lanes to be formatted back into bytes
    * @return byte string formed from state array.
    */
   private byte[] lanesToBytes(long[][] lanes) {
      byte[] result = new byte[myBlockSize.inBytes()];
      
      int byteArrayIndexBase;
      for (int y = 0; y < 5; y++) {
         for (int x = 0; x < 5; x++) {
            byteArrayIndexBase = ((5 * y) + x);
            byte[] temp = long2Bytes(Long.reverseBytes(lanes[x][y]));
            System.arraycopy(temp, 0, result, byteArrayIndexBase * 8, temp.length);
         }
      }
      return result;
   }
   
   /**
    * Helper method to convert a long into an array of its eight constituent bytes.
    * @param num eight-byte integer to be turned into an eight-index byte array
    * @return byte array representing the individual bytes of num
    */
   private byte[] long2Bytes(long num) {
      byte[] result = new byte[8];
      for (int index = 7; index >= 0; index--){
         result[index] = (byte) (num >>> (8 * (7 - index)));
      }
      return result;
   }
}
