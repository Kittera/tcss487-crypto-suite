package com.kittera.crypto487.lib;

import com.kittera.crypto487.lib.enums.KeccakBlockSize;
import com.kittera.crypto487.lib.enums.SHA3Parameters;
import com.kittera.crypto487.lib.interfaces.CryptographicDuplexSponge;
import com.kittera.crypto487.util.ArrayUtils;

import java.util.Arrays;
import java.util.Objects;

/**
 * Library implementing various hash algorithm calls for offering some basic security
 * services.
 */
public class HashLib {
   
   /**
    * Performs SHA3-224 fixed-length hashing on the given string of bytes.
    *
    * @param inputBytes byte array of the input to be processed
    * @return SHA3-224 hash of given input bytes
    */
   public static byte[] SHA3_224(final byte[] inputBytes) {
      return SHA3(inputBytes, SHA3Parameters.SHA3.SHA3_224);
   }
   
   /**
    * Performs SHA3-256 fixed-length hashing on the given string of bytes.
    *
    * @param inputBytes byte array of the input to be processed
    * @return SHA3-256 hash of given input bytes
    */
   public static byte[] SHA3_256(final byte[] inputBytes) {
      return SHA3(inputBytes, SHA3Parameters.SHA3.SHA3_256);
   }
   
   /**
    * Performs SHA3-384 fixed-length hashing on the given string of bytes.
    *
    * @param inputBytes byte array of the input to be processed
    * @return SHA3-384 hash of given input bytes
    */
   public static byte[] SHA3_384(final byte[] inputBytes) {
      return SHA3(inputBytes, SHA3Parameters.SHA3.SHA3_384);
   }
   
   /**
    * Performs SHA3-512 fixed-length hashing on the given string of bytes.
    *
    * @param inputBytes byte array of the input to be processed
    * @return SHA3-512 hash of given input bytes
    */
   public static byte[] SHA3_512(final byte[] inputBytes) {
      return SHA3(inputBytes, SHA3Parameters.SHA3.SHA3_512);
   }
   
   /**
    * Private code factoring method for SHA3 224, 256, 384, 512 fixed-length machinery.
    *
    * @param inputBytes input bytes to be processed
    * @param modeParams parameter enum for SHA3 configurations of Keccak parameters
    * @return message digest
    */
   private static byte[] SHA3(final byte[] inputBytes, final SHA3Parameters.SHA3 modeParams) {
      // SHA3 always uses this block size, Keccak's maximum. Measured in bits.
      final KeccakBlockSize blockSize = KeccakBlockSize.KECCAK_1600;
      
      // instantiate sponge construction
      CryptographicDuplexSponge sponge = new KeccakSponge(
            new KeccakF(SHA3Parameters.KECCAK_NUM_PERM_RNDS, blockSize),
            new PadTenOneSuffixed(modeParams.delimitedSuffix),
            blockSize,
            (modeParams.capacity)
      );
   
      sponge.absorbAll(inputBytes);
      return byteTruncN(sponge.squeeze(), modeParams.inBytes());
   }
   
   
   ////////////////////////////////////////////////////////////////////////// SHAKE //////
   /**
    * Public-facing implementation of SHAKE256. Calls private helper for full function.
    * @param inputBytes byte array of the input to be processed
    * @param outLenInBytes length of the message digest to be output, in BYTES
    * @return byte array of the digest
    */
   public static byte[] SHAKE128(final byte[] inputBytes, final int outLenInBytes) {
      return SHAKE(inputBytes, outLenInBytes, SHA3Parameters.SHAKE.SHAKE128);
   }
   
   /**
    * Public-facing implementation of SHAKE256. Calls private helper for full function.
    * @param inputBytes input byte array to be hashed
    * @param outLenInBytes desired number of output bytes
    * @return byte array of the digest
    */
   public static byte[] SHAKE256(final byte[] inputBytes, final int outLenInBytes) {
      return SHAKE(inputBytes, outLenInBytes, SHA3Parameters.SHAKE.SHAKE256);
   }
   
   /**
    * Private helper function that implements SHAKE.
    * @param inputBytes input byte array to be hashed
    * @param dLen desired number of output bytes
    * @param modeParams enum constant holding SHAKE parameters for keccak
    * @return byte array of the digest
    */
   private static byte[] SHAKE(final byte[] inputBytes,
                               final int dLen,
                               final SHA3Parameters.SHAKE modeParams) {
      // select appropriate block size enum
      final KeccakBlockSize blockSize = KeccakBlockSize.KECCAK_1600;
   
      // instantiate sponge construction
      CryptographicDuplexSponge sponge = new KeccakSponge(
            new KeccakF(SHA3Parameters.KECCAK_NUM_PERM_RNDS, blockSize),
            new PadTenOneSuffixed(modeParams.paddedSuffix),
            blockSize,
            (modeParams.capacity)
      );
      int byteRate = modeParams.inBytes();
      byte[] result = new byte[dLen + byteRate];
      int bytesSqueezed = 0;
      sponge.absorbAll(inputBytes);
      while (bytesSqueezed < dLen) {
         System.arraycopy(sponge.squeeze(), 0, result, bytesSqueezed, byteRate);
         bytesSqueezed += byteRate;
      }
      return Arrays.copyOf(result, dLen);
   }
   
   /**
    * Public-facing implementation of cSHAKE128. Calls private helper for full function.
    * @param inputBytes input byte array to be hashed
    * @param outLenInBytes desired number of output bytes
    * @param functionNameString USED ONLY AS PER NIST DEFINITION
    * @param customizationString Use for domain separation by describing purpose
    * @return byte array of hash using parameterized call to the real function
    */
   public static byte[] cSHAKE128(final byte[] inputBytes,
                               final int outLenInBytes,
                               final String functionNameString,
                               final String customizationString) {
      if (
            (Objects.isNull(functionNameString) && Objects.isNull(customizationString)) ||
                  (functionNameString.equals("") && customizationString.equals(""))
      ) {
         return SHAKE128(inputBytes, outLenInBytes);
      } else return cSHAKE(
            inputBytes,
            outLenInBytes,
            functionNameString,
            customizationString,
            SHA3Parameters.SHAKE.cSHAKE128
      );
   }
   
   /**
    * Public-facing implementation of cSHAKE256. Calls private helper for full function.
    * @param inputBytes input byte array to be hashed
    * @param outLenInBytes desired number of output bytes
    * @param functionNameString USED ONLY AS PER NIST DEFINITION
    * @param customizationString Use for domain separation by describing purpose
    * @return byte array of hash using parameterized call to the real function
    */
   public static byte[] cSHAKE256(final byte[] inputBytes,
                               final int outLenInBytes,
                               final String functionNameString,
                               final String customizationString) {
      if (
            (Objects.isNull(functionNameString) && Objects.isNull(customizationString)) ||
                  (functionNameString.equals("") && customizationString.equals(""))
      ) {
         return SHAKE256(inputBytes, outLenInBytes);
      }else return cSHAKE(
            inputBytes,
            outLenInBytes,
            functionNameString,
            customizationString,
            SHA3Parameters.SHAKE.cSHAKE256
      );
   }
   
   private static byte[] cSHAKE(final byte[] inputBytes,
                               final int outLenInBytes,
                               final String functionNameString,
                               final String customizationString,
                               final SHA3Parameters.SHAKE modeParams) {
      // process add-in strings
      byte[] fNameBytes, cStringBytes;
      fNameBytes = Objects.nonNull(functionNameString) ?
            functionNameString.getBytes() : new byte[]{};
      cStringBytes = Objects.nonNull(customizationString) ?
            customizationString.getBytes() : new byte[]{};
      
      //lots of byte array concatting with some calls to aux functions
      byte[] mergedEncodedStrings = ArrayUtils.mergeByteArrays(
            encodeString(fNameBytes), encodeString(cStringBytes));
      byte[] bytePaddedStrings = bytePad(mergedEncodedStrings, modeParams.inBytes());
      byte[] cattedInput = ArrayUtils.mergeByteArrays(bytePaddedStrings, inputBytes);
      return SHAKE(cattedInput, outLenInBytes, modeParams);
   }
   
   
   //////////////////////////////////////////////////////////////////////// KMACXOF //////
   
   /**
    * Public-facing implementation of KMACXOF128. Calls private helper for full function.
    * @param keyBytes byte array representing an encryption key. Can be empty.
    * @param inputBytes input byte array to be hashed
    * @param outLenInBytes desired number of output bytes
    * @param customizationString Use for domain separation by describing purpose
    * @return MAC or Hash depending on usage; as a byte array
    */
   public static byte[] KMACXOF128(
         final byte[] keyBytes,
         final byte[] inputBytes,
         final int outLenInBytes,
         final String customizationString) {
      return KMACXOF(
            keyBytes,
            inputBytes,
            outLenInBytes,
            customizationString,
            SHA3Parameters.SHAKE.cSHAKE128
      );
   }
   
   /**
    * Public-facing implementation of KMACXOF256. Calls private
    * @param keyBytes byte array representing an encryption key. Can be empty.
    * @param inputBytes input byte array to be hashed
    * @param outLenInBytes desired number of output bytes
    * @param customizationString Use for domain separation by describing purpose
    * @return MAC or Hash depending on usage; as a byte array
    */
   public static byte[] KMACXOF256(
         final byte[] keyBytes,
         final byte[] inputBytes,
         final int outLenInBytes,
         final String customizationString) {
      return KMACXOF(
            keyBytes,
            inputBytes,
            outLenInBytes,
            customizationString,
            SHA3Parameters.SHAKE.cSHAKE256
      );
   }
   
   private static byte[] KMACXOF(
         final byte[] keyBytes,
         final byte[] inputBytes,
         final int outLenInBytes,
         final String customizationString,
         final SHA3Parameters.SHAKE modeParams) {
      
         byte[] mergedInputBytes = // nested call to enact a three-array merge
               ArrayUtils.mergeByteArrays(
                     ArrayUtils.mergeByteArrays(
                           bytePad(encodeString(keyBytes), modeParams.inBytes()),
                           inputBytes
               ),
               lenEncode(0, EncodeDirection.RIGHT)
         );
         
         return cSHAKE(
               mergedInputBytes,
               outLenInBytes,
               "KMAC",
               customizationString,
               modeParams
         );
   }
   
   
   
   /////////////////////////////////////////////////////////// Supporting Functions //////
   
   /**
    * Implements the functionality of outputting only the first n bits/bytes of the sponge
    * state. Input is not changed.
    * @param bytes byte array (should be a re-transformed state array from the sponge)
    *              to truncate
    * @param n number of BYTES to truncate to
    * @return new byte array of truncated state
    */
   protected static byte[] byteTruncN(byte[] bytes, int n) {
      byte[] result = new byte[n];
      System.arraycopy(bytes, 0,result,0, n);
      return result;
   }
   
   /**
    * Given an input bitstring (as a byte array in this case), this method prepends the
    * left-encoding of the wordLength parameter to the input string, then pads that with
    * zeroes until a length (in bytes) which is a multiple of wordLength is achieved.
    * Modified version of NWc0de's example for better clarity.
    * @param inString given bitstring to pad/prepend
    * @param wordLength the padded output is to be of a length in bytes which is a
    *                   multiple of this parameter
    * @return padded byte array result with leftEncode(wordLength) prepended
    */
   protected static byte[] bytePad(byte[] inString, int wordLength) {
      byte[] inStringLeftEncoding =
            lenEncode(wordLength, EncodeDirection.LEFT);
      
      // calculate length of inString plus the leftEncode of wordLength
      int sumOfLengths = inStringLeftEncoding.length + inString.length;
   
      // calculate the final padded length of the bytePad result
      int finalLength = sumOfLengths + (wordLength - (sumOfLengths) % wordLength);
      
      // allocate new buffer, taking advantage of Java's default zero-fill for the 0* pad
      byte[] result = Arrays.copyOf(inStringLeftEncoding, finalLength);
      
      // perform concatenation
      System.arraycopy(
            inString,
            0,
            result,
            inStringLeftEncoding.length,
            inString.length
      );
      
      return result;
   }
   
   /**
    * Implementation of encode_string from NIST SP 800-185 section 2.3.2. Adapted from
    * implementation by NWc0de.
    * @param inString input bitstring as a byte array
    * @return a new bitstring(as another byte array) which is the concatenation of the
    * input string's left encoding and the input string itself.
    */
   protected static byte[] encodeString(byte[] inString) {
      byte[] inStringLeftEncoding =
            lenEncode(inString.length * 8L, EncodeDirection.LEFT);
      
      // allocate a new buffer with room for both things being concatenated
      byte[] result = Arrays.copyOf(
            inStringLeftEncoding, inStringLeftEncoding.length + inString.length);
      
      System.arraycopy( // here's where the concatenation is performed
            inString,
            0,
            result,
            inStringLeftEncoding.length,
            inString.length
      );
      return result;
   }
   
   /**
    * One method to implement both left_ and right_encode from NIST spec,
    * SP 800-185 section 2.3.1. Also adapted from NWc0de's implementation.
    * @param lengthToEncode the big integer that needs to be encoded as a byte string
    * @param encDir whether this method needs to perform a left or right encode
    * @return lengthToEncode encoded as a byte string
    */
   protected static byte[] lenEncode(final long lengthToEncode, final EncodeDirection encDir) {
      byte[] result;
      boolean leftEncode = encDir == EncodeDirection.LEFT;
      
      if (lengthToEncode == 0) { // even a 0 is one byte long, so this is a special case
         result = (leftEncode ? new byte[]{1, 0} : new byte[]{0, 1});
      } else {
         byte[] eightByteBufferForLong = new byte[8]; // encoding byte buffer for 64 bits
         long tempLength = lengthToEncode; // copy of the protected/final value given
         int count = 0; // count how many bytes we end up using for the encoding
         
         while (tempLength > 0) {
            byte thisByte = (byte) (tempLength & 255L); // 255L = 0x00000000000000FFL
            eightByteBufferForLong[7 - count] = thisByte; // append starting at end of buffer
            count++; //increment counter to move the effective pointer back a space
            tempLength = tempLength >>> 8; // shift tempLength by one byte for next round
         }
         
         result = new byte[count + 1]; // new buffer, one extra space for the length byte
         
         int destPos = (leftEncode ? 1 : 0); //determines where the encoded bytes go
         System.arraycopy( // make a deep copy of the buffer into the result array
               eightByteBufferForLong,
               8 - count,
               result,
               destPos,
               count
         );
   
         //where count is to be appended in the final byte array
         int countDestination = (leftEncode? 0 : result.length - 1);
         result[countDestination] = (byte) count; //append the length of the encoded long
      }
      return result;
   }
   
   /**
    * Enum for setting encode direction in an otherwise generic function, in this case
    * lenEncode(). Credit to GitHub user NWc0de for this idea.
    * https://github.com/NWc0de/KeccakUtils/blob/master/src/crypto/keccak/Keccak.java
    */
   public enum EncodeDirection {
      LEFT, RIGHT
   }
}
