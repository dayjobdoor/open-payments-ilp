/**
 * Adapters around the reference implementations (ilp-packet, ilp-protocol-stream, @interledger/stream-receiver)
 * so tests can compare them with this library on equal terms.
 */
import { StreamServer } from "@interledger/stream-receiver";
import * as IlpPacket from "ilp-packet";
import * as Reference from "ilp-protocol-stream/dist/src/packet";
import { generateFulfillmentKey, generatePskEncryptionKey } from "ilp-protocol-stream/dist/src/crypto";
import type { IlpPrepare } from "../../src/ilp";
import type { StreamFrame, StreamPacket } from "../../src/stream";

export { IlpPacket, Reference, StreamServer };

const MAX_UINT64 = (1n << 64n) - 1n;

/** The reference frame object equivalent to `frame` (Long-backed numbers are passed as decimal strings). */
export function referenceFrame(frame: StreamFrame): Reference.Frame {
  switch (frame.type) {
    case "ConnectionClose":
      return new Reference.ConnectionCloseFrame(frame.errorCode, frame.errorMessage);

    case "ConnectionNewAddress":
      return new Reference.ConnectionNewAddressFrame(frame.sourceAccount);

    case "ConnectionAssetDetails":
      return new Reference.ConnectionAssetDetailsFrame(frame.sourceAssetCode, frame.sourceAssetScale);

    case "ConnectionMaxData":
      return new Reference.ConnectionMaxDataFrame(frame.maxOffset.toString());

    case "ConnectionDataBlocked":
      return new Reference.ConnectionDataBlockedFrame(frame.maxOffset.toString());

    case "ConnectionMaxStreamId":
      return new Reference.ConnectionMaxStreamIdFrame(frame.maxStreamId.toString());

    case "ConnectionStreamIdBlocked":
      return new Reference.ConnectionStreamIdBlockedFrame(frame.maxStreamId.toString());

    case "StreamClose":
      return new Reference.StreamCloseFrame(frame.streamId.toString(), frame.errorCode, frame.errorMessage);

    case "StreamMoney":
      return new Reference.StreamMoneyFrame(frame.streamId.toString(), frame.shares.toString());

    case "StreamMaxMoney":
      return new Reference.StreamMaxMoneyFrame(
        frame.streamId.toString(),
        frame.receiveMax.toString(),
        frame.totalReceived.toString(),
      );

    case "StreamMoneyBlocked":
      return new Reference.StreamMoneyBlockedFrame(
        frame.streamId.toString(),
        frame.sendMax.toString(),
        frame.totalSent.toString(),
      );

    case "StreamData":
      return new Reference.StreamDataFrame(frame.streamId.toString(), frame.offset.toString(), Buffer.from(frame.data));

    case "StreamMaxData":
      return new Reference.StreamMaxDataFrame(frame.streamId.toString(), frame.maxOffset.toString());

    case "StreamDataBlocked":
      return new Reference.StreamDataBlockedFrame(frame.streamId.toString(), frame.maxOffset.toString());

    case "StreamReceipt":
      return new Reference.StreamReceiptFrame(frame.streamId.toString(), Buffer.from(frame.receipt));
  }
}

export function referencePacket(packet: StreamPacket): Reference.Packet {
  return new Reference.Packet(
    packet.sequence.toString(),
    packet.ilpPacketType,
    packet.prepareAmount.toString(),
    packet.frames.map(referenceFrame),
  );
}

/** Reference packet → this library's shape, for comparing decoders. */
export function normalizeReference(packet: Reference.Packet): StreamPacket {
  return {
    sequence: BigInt(packet.sequence.toString()),
    ilpPacketType: packet.ilpPacketType,
    prepareAmount: BigInt(packet.prepareAmount.toString()),
    frames: packet.frames.map((frame): StreamFrame => {
      const big = (value: { toString(): string }): bigint => BigInt(value.toString());

      if (frame instanceof Reference.ConnectionCloseFrame) {
        return { type: "ConnectionClose", errorCode: frame.errorCode, errorMessage: frame.errorMessage };
      }

      if (frame instanceof Reference.ConnectionNewAddressFrame) {
        return { type: "ConnectionNewAddress", sourceAccount: frame.sourceAccount };
      }

      if (frame instanceof Reference.ConnectionAssetDetailsFrame) {
        return {
          type: "ConnectionAssetDetails",
          sourceAssetCode: frame.sourceAssetCode,
          sourceAssetScale: frame.sourceAssetScale,
        };
      }

      if (frame instanceof Reference.ConnectionMaxDataFrame) {
        return { type: "ConnectionMaxData", maxOffset: big(frame.maxOffset) };
      }

      if (frame instanceof Reference.ConnectionDataBlockedFrame) {
        return { type: "ConnectionDataBlocked", maxOffset: big(frame.maxOffset) };
      }

      if (frame instanceof Reference.ConnectionMaxStreamIdFrame) {
        return { type: "ConnectionMaxStreamId", maxStreamId: big(frame.maxStreamId) };
      }

      if (frame instanceof Reference.ConnectionStreamIdBlockedFrame) {
        return { type: "ConnectionStreamIdBlocked", maxStreamId: big(frame.maxStreamId) };
      }

      if (frame instanceof Reference.StreamCloseFrame) {
        return {
          type: "StreamClose",
          streamId: big(frame.streamId),
          errorCode: frame.errorCode,
          errorMessage: frame.errorMessage,
        };
      }

      if (frame instanceof Reference.StreamMoneyFrame) {
        return { type: "StreamMoney", streamId: big(frame.streamId), shares: big(frame.shares) };
      }

      if (frame instanceof Reference.StreamMaxMoneyFrame) {
        return {
          type: "StreamMaxMoney",
          streamId: big(frame.streamId),
          receiveMax: big(frame.receiveMax),
          totalReceived: big(frame.totalReceived),
        };
      }

      if (frame instanceof Reference.StreamMoneyBlockedFrame) {
        return {
          type: "StreamMoneyBlocked",
          streamId: big(frame.streamId),
          sendMax: big(frame.sendMax),
          totalSent: big(frame.totalSent),
        };
      }

      if (frame instanceof Reference.StreamDataFrame) {
        return {
          type: "StreamData",
          streamId: big(frame.streamId),
          offset: big(frame.offset),
          data: new Uint8Array(frame.data),
        };
      }

      if (frame instanceof Reference.StreamMaxDataFrame) {
        return { type: "StreamMaxData", streamId: big(frame.streamId), maxOffset: big(frame.maxOffset) };
      }

      if (frame instanceof Reference.StreamDataBlockedFrame) {
        return { type: "StreamDataBlocked", streamId: big(frame.streamId), maxOffset: big(frame.maxOffset) };
      }

      if (frame instanceof Reference.StreamReceiptFrame) {
        return { type: "StreamReceipt", streamId: big(frame.streamId), receipt: new Uint8Array(frame.receipt) };
      }

      throw new Error("unknown reference frame");
    }),
  };
}

export function referencePrepare(prepare: IlpPrepare): IlpPacket.IlpPrepare {
  return {
    amount: prepare.amount.toString(),
    executionCondition: Buffer.from(prepare.executionCondition),
    expiresAt: prepare.expiresAt,
    destination: prepare.destination,
    data: Buffer.from(prepare.data),
  };
}

/** A reference STREAM sender: an encrypted request whose condition is derived like a real sender's. */
export async function referenceRequest(
  sharedSecret: Uint8Array,
  packet: StreamPacket,
  overrides: { readonly condition?: Uint8Array } = {},
): Promise<{ data: Uint8Array; condition: Uint8Array; fulfillment: Uint8Array }> {
  const { createHash, createHmac } = await import("node:crypto");
  const secret = Buffer.from(sharedSecret);
  const data = await referencePacket(packet).serializeAndEncrypt(await generatePskEncryptionKey(secret));

  const fulfillment = createHmac("sha256", await generateFulfillmentKey(secret))
    .update(data)
    .digest();

  const condition = createHash("sha256").update(fulfillment).digest();

  return {
    data: new Uint8Array(data),
    condition: overrides.condition ?? new Uint8Array(condition),
    fulfillment: new Uint8Array(fulfillment),
  };
}

export { MAX_UINT64 };
