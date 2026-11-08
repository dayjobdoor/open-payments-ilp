import * as contract from "../gnap/server/testing/index";
import { toEffectStore } from "../internal/plain-gnap";
import type { GnapStore } from "./gnap-server";

/**
 * Contract tests for a Promise {@link GnapStore}, the plain counterpart of `open-payments-ilp/gnap/server/testing`:
 * register them in your test runner against a fresh store per test.
 */

export type { StoreContractHost, StoreContractOptions } from "../gnap/server/testing/index";

export const storeContract = (
  host: contract.StoreContractHost,
  name: string,
  makeStore: () => GnapStore | Promise<GnapStore>,
  options?: contract.StoreContractOptions,
): void => contract.storeContract(host, name, async () => toEffectStore(await makeStore()), options);
