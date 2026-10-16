import { listen } from "../open-payments/fake-server";
import { describeReferenceClient } from "../gnap-server/reference-flows";
import { IDP_SECRET } from "../gnap-server/support";
import { GNAP_PATH, createHarness } from "./support";

describeReferenceClient("Better Auth adapter over HTTP", async () => {
  let handle: (request: Request) => Promise<Response> = () => Promise.resolve(new Response(null, { status: 503 }));
  const listening = await listen((request) => handle(request));
  const h = await createHarness({ baseURL: listening.origin });

  handle = h.call;

  return {
    authServer: `${listening.origin}${GNAP_PATH}`,
    clientKey: h.clientKey,
    idpSecret: IDP_SECRET,
    advanceClock: h.clock.advance,
    introspect: (token, access) =>
      h.auth.api.gnapIntrospect({ body: { access_token: token, ...(access !== undefined && { access }) } }),
    close: listening.close,
  };
});
