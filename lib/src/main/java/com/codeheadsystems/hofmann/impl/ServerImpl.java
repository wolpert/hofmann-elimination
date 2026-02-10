package com.codeheadsystems.hofmann.impl;

import com.codeheadsystems.hofmann.Curve;
import com.codeheadsystems.hofmann.EliminationRequest;
import com.codeheadsystems.hofmann.EliminationResponse;
import com.codeheadsystems.hofmann.Server;
import java.math.BigInteger;
import java.util.UUID;
import org.bouncycastle.math.ec.ECPoint;

public class ServerImpl implements Server {

  private final ServerData serverData;

  public ServerImpl() {
    serverData = new ServerData(Curve.RANDOM_SCALER(), "SP:" + UUID.randomUUID());
  }

  @Override
  public EliminationResponse process(final EliminationRequest eliminationRequest) {
    // Apply the client key to our master key for this request.
    BigInteger requestKey = serverData.masterKey();
    ECPoint q = Curve.HEX_TO_ECPOINT(eliminationRequest.hexCodedEcPoint());
    ECPoint result = q.multiply(requestKey).normalize();
    return new EliminationResponse(Curve.ECPOINT_TO_HEX(result), serverData.processIdentifier());
  }

  public record ServerData(BigInteger masterKey, String processIdentifier) {

  }

}
