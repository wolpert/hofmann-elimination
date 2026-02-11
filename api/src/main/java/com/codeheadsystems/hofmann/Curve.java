package com.codeheadsystems.hofmann;

import static org.bouncycastle.util.encoders.Hex.decode;
import static org.bouncycastle.util.encoders.Hex.toHexString;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.function.Function;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECPoint;

public interface Curve {

  String DEFAULT_CURVE_NAME = "P-256";
  ECDomainParameters DEFAULT_CURVE = FACTORY().apply(DEFAULT_CURVE_NAME);
  ECDomainParameters SECP256K1_CURVE = FACTORY().apply("secp256k1");
  SecureRandom RANDOM = new SecureRandom();

  static Function<String, ECDomainParameters> FACTORY() {
    return name -> {
      X9ECParameters params = CustomNamedCurves.getByName(name);
      if (params == null) {
        throw new IllegalArgumentException("Unsupported curve: " + name);
      }
      return new ECDomainParameters(
          params.getCurve(),
          params.getG(),
          params.getN(),
          params.getH()
      );
    };
  }

  static byte[] HASH(final byte[] bytes) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return digest.digest(bytes);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException("SHA-256 not available", e);
    }
  }

  /**
   * Integer to Octet String Primitive (I2OSP) from RFC 8017.
   * Converts a non-negative integer to an octet string of specified length.
   */
  static byte[] I2OSP(int value, int length) {
    if (value < 0 || (length < 4 && value >= (1 << (8 * length)))) {
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
   * Generates a random scalar value for use in elliptic curve operations.
   *
   * @return A random scalar value in the range [1, n-1].
   */
  static BigInteger RANDOM_SCALER() {
    BigInteger n = DEFAULT_CURVE.getN();
    BigInteger key;
    do {
      key = new BigInteger(n.bitLength(), RANDOM);
    } while (key.compareTo(BigInteger.ONE) < 0 || key.compareTo(n) >= 0);
    return key;
  }

  static String ECPOINT_TO_HEX(final ECPoint blindedPoint) {
    if (blindedPoint == null) {
      return null;
    }
    byte[] encoded = blindedPoint.getEncoded(true);
    return BYTES_TO_HEX(encoded);
  }

  static ECPoint HEX_TO_ECPOINT(final String hex) {
    if (hex == null || hex.isEmpty()) {
      return null;
    }
    byte[] encoded = decode(hex);
    return DEFAULT_CURVE.getCurve().decodePoint(encoded);
  }

  static String BYTES_TO_HEX(final byte[] bytes) {
    return toHexString(bytes);
  }

}
