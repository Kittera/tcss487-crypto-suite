package com.kittera.crypto487.lib;

import com.kittera.crypto487.lib.interfaces.PaddingRule;
import com.kittera.crypto487.util.ArrayUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class PadTenOneSuffixedTest {
   
   private static PaddingRule plainTenOne;
   private static PaddingRule sha3TenOne;
   private static PaddingRule shakeTenOne;
   private static final int helloLongPaddedBitLength = 128;
   private static final int helloHelloPaddedBitLength = 40;
   private static final int helloSmallPaddedBitLength = 48;
   private static byte[] helloBytes;
   private static byte[] helloLongPlainPadded;
   private static byte[] helloLongSHAPadded;
   private static byte[] helloLongShakePadded;
   private static byte[] helloSmallPlainPadded;
   private static byte[] helloSmallSHAPadded;
   private static byte[] helloSmallShakePadded;
   private static byte[] helloHelloPlainPadded;
   private static byte[] helloHelloSHAPadded;
   private static byte[] helloHelloShakePadded;
   
   @BeforeAll
   static void setUp() {
      plainTenOne = new PadTenOneSuffixed((byte) 0x01);
      sha3TenOne = new PadTenOneSuffixed((byte) 0x06);
      shakeTenOne = new PadTenOneSuffixed((byte) 0x1F);
   
      byte[] helloLongPlainPadding = {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x80};
      byte[] helloLongSHAPadding = {0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x80};
      byte[] helloLongShakePadding = {0x1F, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0x80};
      
      byte[] helloHelloPlainPadding = {0x01, 0, 0, 0, (byte) 0x80};
      byte[] helloHelloSHAPadding = {0x06, 0, 0, 0, (byte) 0x80};
      byte[] helloHelloShakePadding = {0x1F, 0, 0, 0, (byte) 0x80};
      
      byte[] helloSmallPlainPadding = {(byte) 0x81};
      byte[] helloSmallSHAPadding = {(byte) 0x86};
      byte[] helloSmallShakePadding = {(byte) 0x9F};
      helloBytes = "hello".getBytes();
      helloLongPlainPadded = ArrayUtils.mergeByteArrays(helloBytes, helloLongPlainPadding);
      helloLongSHAPadded = ArrayUtils.mergeByteArrays(helloBytes, helloLongSHAPadding);
      helloLongShakePadded = ArrayUtils.mergeByteArrays(helloBytes, helloLongShakePadding);
      
      helloHelloPlainPadded = ArrayUtils.mergeByteArrays(helloBytes, helloHelloPlainPadding);
      helloHelloSHAPadded = ArrayUtils.mergeByteArrays(helloBytes, helloHelloSHAPadding);
      helloHelloShakePadded = ArrayUtils.mergeByteArrays(helloBytes, helloHelloShakePadding);
      
      helloSmallPlainPadded = ArrayUtils.mergeByteArrays(helloBytes, helloSmallPlainPadding);
      helloSmallSHAPadded = ArrayUtils.mergeByteArrays(helloBytes, helloSmallSHAPadding);
      helloSmallShakePadded = ArrayUtils.mergeByteArrays(helloBytes, helloSmallShakePadding);
   }
   
   @Test
   void testPadSuffix0_1() {
      assertArrayEquals(
            helloLongPlainPadded,
            plainTenOne.apply(helloBytes, helloLongPaddedBitLength),
            "Testing plain pad10*1 on \"hello\""
      );
      assertArrayEquals(
            helloLongSHAPadded,
            sha3TenOne.apply(helloBytes, helloLongPaddedBitLength),
            "Testing SHA3 pad10*1 on \"hello\""
      );
      assertArrayEquals(
            helloLongShakePadded,
            shakeTenOne.apply(helloBytes, helloLongPaddedBitLength),
            "Testing SHAKE pad10*1 on \"hello\""
      );
   
      assertArrayEquals(
            helloHelloPlainPadded,
            plainTenOne.apply(helloBytes,helloHelloPaddedBitLength),
            "Testing plain pad10*1 on \"hello\" with 0 bytes needed"
      );
      assertArrayEquals(
            helloHelloSHAPadded,
            sha3TenOne.apply(helloBytes,helloHelloPaddedBitLength),
            "Testing SHA3 pad10*1 on \"hello\" with 0 bytes needed"
      );
      assertArrayEquals(
            helloHelloShakePadded,
            shakeTenOne.apply(helloBytes,helloHelloPaddedBitLength),
            "Testing SHAKE pad10*1 on \"hello\" with 0 bytes needed"
      );
   
      assertArrayEquals(
            helloSmallPlainPadded,
            plainTenOne.apply(helloBytes,helloSmallPaddedBitLength),
            "Testing plain pad10*1 on \"hello\" with one byte needed"
      );
      assertArrayEquals(
            helloSmallSHAPadded,
            sha3TenOne.apply(helloBytes,helloSmallPaddedBitLength),
            "Testing sha3 pad10*1 on \"hello\" with one byte needed"
      );
      assertArrayEquals(
            helloSmallShakePadded,
            shakeTenOne.apply(helloBytes,helloSmallPaddedBitLength),
            "Testing SHAKE pad10*1 on \"hello\" with one byte needed"
      );
   }
}
