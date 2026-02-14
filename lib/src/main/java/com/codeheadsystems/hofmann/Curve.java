package com.codeheadsystems.hofmann;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.function.Function;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public record Curve(ECDomainParameters params, ECCurve curve, ECPoint g, BigInteger n, BigInteger h) {

  public static Curve P256_CURVE = new Curve(FACTORY().apply("P-256"));
  public static Curve SECP256K1_CURVE = new Curve(FACTORY().apply("secp256k1"));
  private static SecureRandom RANDOM = new SecureRandom();

  public Curve(ECDomainParameters params) {
    this(params, params.getCurve(), params.getG(), params.getN(), params.getH());
  }

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

  /**
   * Generates a random scalar value for use in elliptic curve operations.
   *
   * @return A random scalar value in the range [1, n-1].
   */
  public BigInteger randomScaler() {
    BigInteger n = n();
    BigInteger key;
    do {
      key = new BigInteger(n.bitLength(), RANDOM);
    } while (key.compareTo(BigInteger.ONE) < 0 || key.compareTo(n) >= 0);
    return key;
  }

}
