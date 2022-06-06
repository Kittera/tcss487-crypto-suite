package com.kittera.crypto487.lib;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

import static com.kittera.crypto487.lib.E521CurveLib.*;

/**
 * Class implementing points on the E521 Edwards Curve.
 * Operations: Abelian point addition, scalar multiplication, shortcut for doubling, negation.
 *
 * @author Kittera McCloud
 */
public class E521Point {
   private final BigInteger xCoord;
   private final BigInteger yCoord;
   
////////////////////////////////////////////////////////////////////// Constructors //////
   
   /**
    * "Default" constructor, uses BigIntegers.
    * @param xCand BigInteger x-coordinate
    * @param yCand BigInteger y-coordinate
    */
   public E521Point(BigInteger xCand, BigInteger yCand) {
      if (!testCurveCoordinates(xCand, yCand)) {
         throw new IllegalArgumentException(
               "Given coordinates do not correspond to a valid point on E521."
         );
      }
      xCoord = xCand;
      yCoord = yCand;
   }
   
   /**
    * Constructor for providing longs, which will be converted into BigIntegers for the
    * default constructor.
    * @param x x-coordinate as a long
    * @param y y-coordinate as a long
    */
   public E521Point(long x, long y) {
      this(BigInteger.valueOf(x), BigInteger.valueOf(y));
   }
   
   /**
    * Builds an E521point from a given x-coordinate by solving the curve equation using
    * a modular square root algorithm
    * @param xCand candidate x-coordinate
    * @param lsb whether y must be even.
    */
   public E521Point(BigInteger xCand, boolean lsb) {
      BigInteger xSquared, top, bot, radicand, yCand;
      xSquared = xCand.multiply(xCand).mod(P521); // x^2
      top = BigInteger.ONE.subtract(xSquared).mod(P521); // (1 - x^2)
      bot = BigInteger.ONE.subtract(D521.multiply(xSquared)).mod(P521); // (1 - dx^2)
      // (1 - x^2)/(1 - dx^2) (mod p)
      radicand = top.multiply(bot.modInverse(P521)).mod(P521);
   
      yCand = sqrt(radicand, P521, lsb);
      if (Objects.isNull(yCand))
         throw new IllegalArgumentException("Given x-coord has no corresponding y-coord.");
      
      this.xCoord = xCand;
      this.yCoord = yCand;
   }
   
///////////////////////////////////////////////////////////////////////// Accessors //////
   
   /**
    * X coordinate accessor.
    * @return X coordinate as BigInteger
    */
   public BigInteger xCoord() {
      return this.xCoord;
   }
   
   /**
    * Y coordinate accessor.
    * @return Y coordinate as BigInteger
    */
   public BigInteger yCoord() {
      return this.yCoord;
   }
   
//////////////////////////////////////////////////// Edwards Curve Point Operations //////
   
   /**
    * Addition formula for the E521 abelian group.
    *
    * @param thePoint another curve point to be "added" to this point
    * @return new point representing the "sum" of this and thePoint
    */
   public E521Point curvePtAdd(E521Point thePoint) {
      BigInteger x1 = xCoord, y1 = yCoord;
      BigInteger x2 = thePoint.xCoord, y2 = thePoint.yCoord;
      
      BigInteger denominatorBase =
            x1.multiply(x2).mod(P521)
                  .multiply(y1).mod(P521)
                  .multiply(y2).mod(P521)
                  .multiply(D521).mod(P521);
      
      // calculate new x
      BigInteger numerator1 =
            (x1.multiply(y2)).mod(P521)
                  .add(y1.multiply(x2).mod(P521))
                  .mod(P521);
      BigInteger denominator1 = BigInteger.ONE.add(denominatorBase).mod(P521);
      BigInteger x3 = numerator1.multiply(denominator1.modInverse(P521)).mod(P521);
   
      // calculate new y
      BigInteger numerator2 =
            (y1.multiply(y2)).mod(P521)
                  .subtract(x1.multiply(x2).mod(P521))
                  .mod(P521);
      BigInteger denominator2 = BigInteger.ONE.subtract(denominatorBase).mod(P521);
      BigInteger y3 = numerator2.multiply(denominator2.modInverse(P521)).mod(P521);
      
      return new E521Point(x3, y3);
   }
   
   /**
    * Shortcut method for doubling a point. Given P, performs Abelian calculation for
    * 2 * P.
    * @return this "+" this, or 2 * this
    */
   public E521Point doubled() {
      return this.curvePtAdd(this);
   }
   
   /**
    * Returns the Edwardian negative of this curve point.
    * @return a new Point like this one, but with a negated x coordinate
    */
   public E521Point negate() {
      return new E521Point(this.xCoord.negate().mod(P521), this.yCoord);
   }
   
   /**
    * Implements the Abelian scalar multiplication algorithm in double-and-add form.
    * @param scalar scalar by which to multiply this point
    * @return the desired multiple, s "*" this
    */
   public E521Point scalarMultiply(BigInteger scalar) {
      E521Point result = E521CurveLib.E521_PT_AT_INFTY;
      for (int i = scalar.bitLength() - 1; i >= 0; i--) {
         result = result.doubled(); // double...
         if (scalar.testBit(i)) result = result.curvePtAdd(this); // ...and add.
      }
      return result;
   }
   
/////////////////////////////////////////////////////////////////// Utility Methods //////
   
   /**
    * Generates a byte array containing a representation of this point's coordinates as a
    * "single value."
    *
    * @return byte array representation of this E521Point
    */
   public byte[] toByteArray() {
      byte[] result = new byte[E521CurveLib.EC_PT_BYTELEN], xBytes, yBytes;
      int midIndex, xPosition, yPosition;
      
      //grab x and y coordinate values as bytes
      xBytes = xCoord.toByteArray();
      yBytes = yCoord.toByteArray();
   
      //calculate some indexes
      midIndex = EC_PT_BYTELEN / 2;
      xPosition = midIndex - xBytes.length;
      yPosition = EC_PT_BYTELEN - yBytes.length;
   
      // sign extend if necessary
      if (xCoord.signum() < 0) Arrays.fill(result, 0, xPosition, (byte) 0xFF);
      if (yCoord.signum() < 0) Arrays.fill(result, midIndex, yPosition, (byte) 0xFF);
   
      //populate bytes
      System.arraycopy(xBytes, 0, result, xPosition, xBytes.length);
      System.arraycopy(yBytes, 0, result, yPosition, yBytes.length);
   
      return result;
   }
   
   /**
    * Determines whether the provided x and y coordinate pair are a valid point on E521
    * by plugging them into the E521 formula.
    * The E521 formula: x^2 + y^2 = 1 + d * (x^2) * y^2 where d = -376014
    *
    * Modified version of NWc0de's implementation for better clarity.
    * @param xCand candidate x-coordinate
    * @param yCand candidate y-coordinate
    * @return boolean: whether the provided (x, y) pair is a valid point on E521
    */
   private boolean testCurveCoordinates(final BigInteger xCand, final BigInteger yCand) {
      BigInteger left, right;
      boolean result;
   
      // BigInteger throws exception when computing 1 mod p; let's avoid that.
      if (xCand.equals(BigInteger.ZERO) && yCand.equals(BigInteger.ONE)) result = true;
      else {
         // left side of curve EQ: (x^2 + y^2) mod p
         left = xCand.pow(2)
               .add(yCand.pow(2))
               .mod(P521);
         
         // right side of curve EQ: (1 + d * x^2 * y^2) mod p
         // this is what makes the if-else block necessary; D521.mult(...) might result in 0
         right = BigInteger.ONE.add(
               D521.multiply(
                     xCand.pow(2).multiply(yCand.pow(2)
               ))
         ).mod(P521);
         
         // test left and right sides of equation for equality
         result = left.equals(right);
      }
      return result;
   }
   
/////////////////////////////////////////////////////////// Standard Object Methods //////
   
   /**
    * Tests two points for equality using their x and y values.
    * @param incoming the other point to compare against
    * @return true if points are equal, false otherwise
    */
   @Override
   public boolean equals(Object incoming) {
      if (this == incoming) return true;
      if (incoming == null || getClass() != incoming.getClass()) return false;
      
      E521Point otherPoint = (E521Point) incoming;
      
      return xCoord.equals(otherPoint.xCoord()) && yCoord.equals(otherPoint.yCoord());
   }
   
   /**
    * toString method for an E521Point. Gives x and y coordinates.
    * @return string representation
    */
   public String toString() {
      return "E521 Pt: " + String.format("x = %d, ", this.xCoord) +
            String.format("y = %d", this.yCoord);
   }
}
