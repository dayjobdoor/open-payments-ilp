import * as Effect from "effect/Effect";
import { listen } from "../open-payments/fake-server";
import { describeReferenceClient } from "./reference-flows";
import { IDP_SECRET, createServerHarness } from "./support";

describeReferenceClient("bare core over HTTP", async () => {
  let handle: (request: Request) => Promise<Response> = () => Promise.resolve(new Response(null, { status: 503 }));
  const listening = await listen((request) => handle(request));
  const h = await createServerHarness({ baseUrl: `${listening.origin}/gnap` });

  handle = h.call;

  return {
    authServer: h.baseUrl,
    clientKey: h.clientKey,
    idpSecret: IDP_SECRET,
    advanceClock: h.clock.advance,
    introspect: (token, access) => Effect.runPromise(h.server.introspectToken(token, access)),
    close: listening.close,
  };
});
