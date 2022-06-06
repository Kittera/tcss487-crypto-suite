package com.kittera.crypto487.lib;

import java.math.BigInteger;
import java.util.Arrays;


/**
 * Library class containing several E521 constants and some other utility or arithmetic
 * methods.
 */
public class E521CurveLib {
   
   public static final BigInteger FOUR = BigInteger.valueOf(4);
   
   /**
    * Value used to calculate r for E521.
    */
   private static final BigInteger R521_ =
         new BigInteger("337554763258501705789107630418782636071904961214051226618635150085779108655765");
   
   /**
    * Parameter D, a strategically chosen value that defines the curve equation.
    */
   public static final BigInteger D521 = BigInteger.valueOf(-376014);
   
   /**
    * Parameter P, a Mersenne prime definining the finite field F_p. All operations are
    * done under this modulus.
    */
   public static final BigInteger P521 =
         BigInteger.TWO.pow(521).subtract(BigInteger.ONE);
   
   /**
    * There are four times this number of points on the curve.
    */
   public static final BigInteger R521 =
         BigInteger.TWO.pow(519).subtract(R521_);
   
   /**
    * This is the "O" point of the E521 Abelian group.
    */
   public static final E521Point E521_PT_AT_INFTY =
         new E521Point(BigInteger.ZERO, BigInteger.ONE);
   
   /**
    * Calculates the length needed for an array that will hold the byte representation of
    * a given E521point's coordinates.
    */
   public static final int EC_PT_BYTELEN = P521.toByteArray().length * 2;
   
   /**
    * Constructs the generator point G for E521 using special constructor.
    *
    * @return E521's public generator point
    */
   public static E521Point constructGenerator() {
      return new E521Point(
            BigInteger.valueOf(4),
            false // lsb = false(aka 0) -> result will be even
      );
   }
   
   /**
    * Compute a square root of v mod p with a specified
    * least significant bit, if such a root exists.
    *
    * @param v   the radicand.
    * @param p   the modulus (must satisfy p mod 4 = 3).
    * @param lsb desired least significant bit (true: 1, false: 0).
    * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
    * if such a root exists, otherwise null.
    * @author Paulo Barretto?
    */
   public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
      assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
      if (v.signum() == 0) {
         return BigInteger.ZERO;
      }
      BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
      if (r.testBit(0) != lsb) {
         r = p.subtract(r); // correct the lsb
      }
      return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
   }
   
   /**
    * Attempts to parse a byte array to construct a point.
    *
    * @param coordBytes byte array containing x and y coordinates.
    * @return resulting point on E521
    */
   public static E521Point pointFromBytes(byte[] coordBytes) {
      BigInteger x, y;
      int midIndex;
      if (coordBytes.length != EC_PT_BYTELEN)
         throw new IllegalArgumentException("Improperly formatted byte array; cannot construct point.");
      else {
         midIndex = EC_PT_BYTELEN / 2;
         x = new BigInteger(Arrays.copyOfRange(coordBytes, 0, midIndex));
         y = new BigInteger(Arrays.copyOfRange(coordBytes, midIndex, EC_PT_BYTELEN));
         return new E521Point(x, y);
      }
   }
}
