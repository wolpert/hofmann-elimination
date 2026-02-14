package com.codeheadsystems.hofmann.curve;

import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;

/**
 * Utility methods for octet string encoding and EC point serialization.
 */
public class OctetStringUtils {

  private OctetStringUtils() {}

  /**
   * Integer to Octet String Primitive (I2OSP) from RFC 8017.
   * Converts a non-negative integer to an octet string of specified length.
   */
  public static byte[] I2OSP(int value, int length) {
    if (value < 0 || value >= (1L << (8 * length))) {
      throw new IllegalArgumentException("Value too large for specified length");
    }
    byte[] result = new byte[length];
    for (int i = length - 1; i >= 0; i--) {
      result[i] = (byte) (value & 0xFF);
      value >>= 8;
    }
    return result;
  }

  /**
   * Serializes an EC point to a compressed hex string.
   */
  public static String toHex(final ECPoint point) {
    if (point == null) {
      throw new IllegalArgumentException("EC point must not be null");
    }
    return Hex.toHexString(point.getEncoded(true));
  }

  /**
   * Deserializes a compressed hex string to an EC point on the given curve.
   */
  public static ECPoint toEcPoint(final Curve curve, final String hex) {
    if (hex == null || hex.isEmpty()) {
      throw new IllegalArgumentException("Hex string must not be null or empty");
    }
    return curve.params().getCurve().decodePoint(Hex.decode(hex));
  }

}
