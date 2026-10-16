import * as Result from "effect/Result";
import { parseAmountValue } from "./amount";
import { OpenPaymentsError } from "./errors";
import type {
  IncomingPayment,
  IncomingPaymentWithPaymentMethods,
  OutgoingPayment,
  OutgoingPaymentWithSpentAmounts,
} from "./types";

const violation = (message: string): Result.Result<never, OpenPaymentsError> =>
  Result.fail(
    new OpenPaymentsError({ reason: "validation", message, description: message, validationErrors: [message] }),
  );

/** Incoming payment invariant: the incoming amount shares the received amount's asset. */
export function checkIncomingPayment<T extends IncomingPayment>(payment: T): Result.Result<T, OpenPaymentsError> {
  const { incomingAmount, receivedAmount } = payment;

  if (
    incomingAmount &&
    (incomingAmount.assetCode !== receivedAmount.assetCode || incomingAmount.assetScale !== receivedAmount.assetScale)
  ) {
    return violation("Incoming amount asset code or asset scale does not match up received amount");
  }

  return Result.succeed(payment);
}

/** A freshly created incoming payment has received nothing and is not completed. */
export function checkCreatedIncomingPayment(
  payment: IncomingPaymentWithPaymentMethods,
): Result.Result<IncomingPaymentWithPaymentMethods, OpenPaymentsError> {
  const received = parseAmountValue(payment.receivedAmount.value);

  if (Result.isFailure(received)) return Result.fail(received.failure);

  if (received.success !== 0n) return violation("Received amount is a non-zero value");

  if (payment.completed) return violation("Can not create a completed incoming payment");

  return checkIncomingPayment(payment);
}

/** The result of `complete` must be completed. */
export function checkCompletedIncomingPayment(
  payment: IncomingPayment,
): Result.Result<IncomingPayment, OpenPaymentsError> {
  if (!payment.completed) return violation("Incoming payment could not be completed");

  return checkIncomingPayment(payment);
}

/** Outgoing payment invariants: same asset for debit and sent, sent ≤ debit, and a failed payment did not send everything. */
export function checkOutgoingPayment<T extends OutgoingPayment | OutgoingPaymentWithSpentAmounts>(
  payment: T,
): Result.Result<T, OpenPaymentsError> {
  const { debitAmount, sentAmount } = payment;

  if (debitAmount.assetCode !== sentAmount.assetCode || debitAmount.assetScale !== sentAmount.assetScale) {
    return violation("Asset code or asset scale of sending amount does not match sent amount");
  }

  const debit = parseAmountValue(debitAmount.value);

  if (Result.isFailure(debit)) return Result.fail(debit.failure);
  const sent = parseAmountValue(sentAmount.value);

  if (Result.isFailure(sent)) return Result.fail(sent.failure);

  if (debit.success < sent.success) return violation("Amount sent is larger than maximum amount to send");

  if (debit.success === sent.success && payment.failed) {
    return violation("Amount to send matches sent amount but payment failed");
  }

  return Result.succeed(payment);
}
