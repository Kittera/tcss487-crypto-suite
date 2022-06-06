package com.kittera.crypto487.lib;

import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

import static com.kittera.crypto487.lib.E521CurveLib.*;
import static org.junit.jupiter.api.Assertions.*;

class E521PointTest {
   private static final E521Point G = constructGenerator();
   private static final E521Point O = E521_PT_AT_INFTY;
   
   private static final BigInteger FOUR = BigInteger.valueOf(4);
   
   
   @Test
   void arithmeticProperties() {
      E521Point twoTimesTwoTimesG =
            G.scalarMultiply(BigInteger.TWO).scalarMultiply(BigInteger.TWO);
            
      assertEquals(O, G.scalarMultiply(BigInteger.ZERO));
      assertEquals(G, G.scalarMultiply(BigInteger.ONE));
      assertEquals(G.scalarMultiply(BigInteger.TWO), G.curvePtAdd(G));
      assertEquals(G.scalarMultiply(FOUR), twoTimesTwoTimesG);
      assertEquals(O, G.scalarMultiply(R521));
      assertEquals(O, G.curvePtAdd(G.negate()));
      assertNotEquals(O, G.scalarMultiply(FOUR));
   }
   
   @Test
   void randomIntTest() {
      SecureRandom sRand = new SecureRandom();
      int i = 0;
      while (i++ < 1000) {
         testInstance(sRand.nextInt(Integer.MAX_VALUE), sRand.nextInt(Integer.MAX_VALUE));
      }
   }
   
   void testInstance(int k, int t) {
      BigInteger K, T;
      K = BigInteger.valueOf(k);
      T = BigInteger.valueOf(t);
      assertEquals(
            G.scalarMultiply(BigInteger.ONE.add(K)),
            G.scalarMultiply(K).curvePtAdd(G)
      );
      assertEquals(
            G.scalarMultiply(T.add(K)),
            G.scalarMultiply(K).curvePtAdd(G.scalarMultiply(T))
      );
      
   }
   
}
