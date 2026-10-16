import type * as Upstream from "@interledger/open-payments/dist/types";
import { AccessAction, AccessType } from "@interledger/open-payments";
import { describe, expect, it } from "vite-plus/test";
import * as Ours from "../../src/open-payments/index";

type Mutual<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

/** Fails to compile unless every pair is mutually assignable. */
type AllMutual<T extends Record<string, true>> = T;

// Every type alias exported by @interledger/open-payments' types.d.ts that Open Payments clients depend on. Vitest
// does not type-check: this table is enforced by `tsc -p tsconfig.test.json` (part of `prepublishOnly`).
export type Compat = AllMutual<{
  WalletAddress: Mutual<Ours.WalletAddress, Upstream.WalletAddress>;
  JWK: Mutual<Ours.JWK, Upstream.JWK>;
  JWKS: Mutual<Ours.JWKS, Upstream.JWKS>;
  DIDDocument: Mutual<Ours.DIDDocument, Upstream.DIDDocument>;
  IncomingPayment: Mutual<Ours.IncomingPayment, Upstream.IncomingPayment>;
  PublicIncomingPayment: Mutual<Ours.PublicIncomingPayment, Upstream.PublicIncomingPayment>;
  IlpPaymentMethod: Mutual<Ours.IlpPaymentMethod, Upstream.IlpPaymentMethod>;
  IncomingPaymentWithPaymentMethods: Mutual<
    Ours.IncomingPaymentWithPaymentMethods,
    Upstream.IncomingPaymentWithPaymentMethods
  >;
  CreateIncomingPaymentArgs: Mutual<Ours.CreateIncomingPaymentArgs, Upstream.CreateIncomingPaymentArgs>;
  IncomingPaymentPaginationResult: Mutual<
    Ours.IncomingPaymentPaginationResult,
    Upstream.IncomingPaymentPaginationResult
  >;
  OutgoingPayment: Mutual<Ours.OutgoingPayment, Upstream.OutgoingPayment>;
  OutgoingPaymentWithSpentAmounts: Mutual<
    Ours.OutgoingPaymentWithSpentAmounts,
    Upstream.OutgoingPaymentWithSpentAmounts
  >;
  OutgoingPaymentGrantSpentAmounts: Mutual<
    Ours.OutgoingPaymentGrantSpentAmounts,
    Upstream.OutgoingPaymentGrantSpentAmounts
  >;
  CreateOutgoingPaymentArgs: Mutual<Ours.CreateOutgoingPaymentArgs, Upstream.CreateOutgoingPaymentArgs>;
  OutgoingPaymentPaginationResult: Mutual<
    Ours.OutgoingPaymentPaginationResult,
    Upstream.OutgoingPaymentPaginationResult
  >;
  ForwardPagination: Mutual<Ours.ForwardPagination, Upstream.ForwardPagination>;
  BackwardPagination: Mutual<Ours.BackwardPagination, Upstream.BackwardPagination>;
  PaginationArgs: Mutual<Ours.PaginationArgs, Upstream.PaginationArgs>;
  Quote: Mutual<Ours.Quote, Upstream.Quote>;
  CreateQuoteArgs: Mutual<Ours.CreateQuoteArgs, Upstream.CreateQuoteArgs>;
  Subject: Mutual<Ours.Subject, Upstream.Subject>;
  Client: Mutual<Ours.Client, Upstream.Client>;
  NonInteractiveGrantRequest: Mutual<Ours.NonInteractiveGrantRequest, Upstream.NonInteractiveGrantRequest>;
  GrantRequest: Mutual<Ours.GrantRequest, Upstream.GrantRequest>;
  Grant: Mutual<Ours.Grant, Upstream.Grant>;
  GrantWithAccessToken: Mutual<Ours.GrantWithAccessToken, Upstream.GrantWithAccessToken>;
  GrantWithSubject: Mutual<Ours.GrantWithSubject, Upstream.GrantWithSubject>;
  GrantContinuation: Mutual<Ours.GrantContinuation, Upstream.GrantContinuation>;
  GrantContinuationRequest: Mutual<Ours.GrantContinuationRequest, Upstream.GrantContinuationRequest>;
  PendingGrant: Mutual<Ours.PendingGrant, Upstream.PendingGrant>;
  AccessToken: Mutual<Ours.AccessToken, Upstream.AccessToken>;
  AccessIncomingActions: Mutual<Ours.AccessIncomingActions, Upstream.AccessIncomingActions>;
  AccessOutgoingActions: Mutual<Ours.AccessOutgoingActions, Upstream.AccessOutgoingActions>;
  AccessQuoteActions: Mutual<Ours.AccessQuoteActions, Upstream.AccessQuoteActions>;
  AccessItem: Mutual<Ours.AccessItem, Upstream.AccessItem>;
  AccessType: Mutual<Ours.AccessType, Upstream.AccessType>;
  AccessAction: Mutual<Ours.AccessAction, Upstream.AccessAction>;
  AccessOutgoingBase: Mutual<Ours.AccessOutgoingBase, Upstream.AccessOutgoingBase>;
  AccessOutgoingWithDebitAmount: Mutual<Ours.AccessOutgoingWithDebitAmount, Upstream.AccessOutgoingWithDebitAmount>;
  AccessOutgoingWithReceiveAmount: Mutual<
    Ours.AccessOutgoingWithReceiveAmount,
    Upstream.AccessOutgoingWithReceiveAmount
  >;
  AccessOutgoingLimits: Mutual<Ours.AccessOutgoingLimits, Upstream.AccessOutgoingLimits>;
  AccessOutgoing: Mutual<Ours.AccessOutgoing, Upstream.AccessOutgoing>;
  GrantRequestAccessItem: Mutual<Ours.GrantRequestAccessItem, Upstream.GrantRequestAccessItem>;
}>;

describe("type compatibility with @interledger/open-payments", () => {
  it("has the same runtime constants", () => {
    expect(Ours.AccessType).toEqual(AccessType);
    expect(Ours.AccessAction).toEqual(AccessAction);
  });
});
