import 'dart:async';
import 'package:flutter_test/flutter_test.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

void main() {
  test('Full Signaling Flow Test: Offer, Answer, ICE exchange', () async {
    const url = 'https://kyojroqhbvadzocdpnqn.supabase.co';
    const anonKey = 'sb_publishable_trcpGuxjaKxTlb8Sa-b8vA_qWRPTwTf';

    final client1 = SupabaseClient(url, anonKey);
    final client2 = SupabaseClient(url, anonKey);

    const client1Id = 'sender_uuid_1111';
    const client2Id = 'receiver_uuid_2222';

    final offerCompleter = Completer<Map<String, dynamic>>();
    final answerCompleter = Completer<Map<String, dynamic>>();
    final iceCompleter = Completer<Map<String, dynamic>>();

    void parseIncomingSignal(
      Map<String, dynamic> raw,
      String myUuid,
      void Function(String type, String senderId, Map<String, dynamic> payload) onSignal,
    ) {
      Map<String, dynamic> msg = raw;
      if (raw.containsKey('payload') && raw['payload'] is Map<String, dynamic>) {
        final inner = raw['payload'] as Map<String, dynamic>;
        if (inner.containsKey('target_id') || inner.containsKey('signal_type') || inner.containsKey('sender_id')) {
          msg = inner;
        }
      }

      final rawTargetId = msg['target_id']?.toString();
      if (rawTargetId == null) return;

      if (rawTargetId.trim().toLowerCase() != myUuid.trim().toLowerCase()) {
        return; // Not for this client
      }

      final signalPayload = msg['payload'] is Map<String, dynamic>
          ? msg['payload'] as Map<String, dynamic>
          : <String, dynamic>{};

      // Detect signal type reliably even if Supabase injects type: "broadcast"
      String? type = msg['signal_type']?.toString();
      if (type == null || type == 'broadcast') {
        if (msg['type'] != null && msg['type'] != 'broadcast') {
          type = msg['type'].toString();
        } else if (signalPayload.containsKey('sdp')) {
          type = signalPayload['type']?.toString() ?? 'offer';
        } else if (signalPayload.containsKey('candidate')) {
          type = 'ice';
        } else if (signalPayload.containsKey('error')) {
          type = 'error';
        }
      }

      final senderId = msg['sender_id']?.toString() ?? 'unknown';
      if (type != null) {
        onSignal(type, senderId, signalPayload);
      }
    }

    final ch1 = client1.channel(
      'kerberos_test_full_handshake',
      opts: const RealtimeChannelConfig(),
    );
    final ch2 = client2.channel(
      'kerberos_test_full_handshake',
      opts: const RealtimeChannelConfig(),
    );

    ch1.onBroadcast(
      event: 'signal',
      callback: (raw) {
        parseIncomingSignal(raw, client1Id, (type, senderId, payload) {
          print("Client 1 parsed signal: $type from $senderId");
          if (type == 'answer') {
            answerCompleter.complete(payload);
          } else if (type == 'ice') {
            iceCompleter.complete(payload);
          }
        });
      },
    );

    ch2.onBroadcast(
      event: 'signal',
      callback: (raw) {
        parseIncomingSignal(raw, client2Id, (type, senderId, payload) {
          print("Client 2 parsed signal: $type from $senderId");
          if (type == 'offer') {
            offerCompleter.complete(payload);
          }
        });
      },
    );

    final ch1Subscribed = Completer<void>();
    final ch2Subscribed = Completer<void>();

    ch1.subscribe((status, [err]) {
      print("ch1 status: $status, err: $err");
      if (status == RealtimeSubscribeStatus.subscribed && !ch1Subscribed.isCompleted) {
        ch1Subscribed.complete();
      }
    });

    ch2.subscribe((status, [err]) {
      print("ch2 status: $status, err: $err");
      if (status == RealtimeSubscribeStatus.subscribed && !ch2Subscribed.isCompleted) {
        ch2Subscribed.complete();
      }
    });

    // Await both channels to be confirmed subscribed by the server
    await Future.wait([
      ch1Subscribed.future.timeout(const Duration(seconds: 10)),
      ch2Subscribed.future.timeout(const Duration(seconds: 10)),
    ]);
    print("Both channels are confirmed SUBSCRIBED!");

    // 1. Client 1 sends SDP Offer
    print("Step 1: Client 1 sending SDP Offer to Client 2...");
    final offerResp = await ch1.sendBroadcastMessage(
      event: 'signal',
      payload: {
        'sender_id': client1Id,
        'target_id': client2Id,
        'signal_type': 'offer',
        'type': 'offer',
        'payload': {'sdp': 'v=0\r\no=test 12345 IN IP4 0.0.0.0...', 'type': 'offer'},
      },
    );
    expect(offerResp, equals(ChannelResponse.ok));

    // Await Offer on Client 2
    final receivedOffer = await offerCompleter.future.timeout(const Duration(seconds: 5));
    print("SUCCESS: Client 2 received offer: ${receivedOffer['type']}");
    expect(receivedOffer['type'], equals('offer'));

    // 2. Client 2 sends SDP Answer back to Client 1
    print("Step 2: Client 2 sending SDP Answer to Client 1...");
    final answerResp = await ch2.sendBroadcastMessage(
      event: 'signal',
      payload: {
        'sender_id': client2Id,
        'target_id': client1Id,
        'signal_type': 'answer',
        'type': 'answer',
        'payload': {'sdp': 'v=0\r\no=answer 67890 IN IP4 0.0.0.0...', 'type': 'answer'},
      },
    );
    expect(answerResp, equals(ChannelResponse.ok));

    // Await Answer on Client 1
    final receivedAnswer = await answerCompleter.future.timeout(const Duration(seconds: 5));
    print("SUCCESS: Client 1 received answer: ${receivedAnswer['type']}");
    expect(receivedAnswer['type'], equals('answer'));

    // 3. Client 2 sends ICE Candidate to Client 1
    print("Step 3: Client 2 sending ICE candidate to Client 1...");
    final iceResp = await ch2.sendBroadcastMessage(
      event: 'signal',
      payload: {
        'sender_id': client2Id,
        'target_id': client1Id,
        'signal_type': 'ice',
        'type': 'ice',
        'payload': {'candidate': 'candidate:1 1 UDP 2122260223 192.168.1.100 54321 typ host', 'sdpMid': '0'},
      },
    );
    expect(iceResp, equals(ChannelResponse.ok));

    final receivedIce = await iceCompleter.future.timeout(const Duration(seconds: 5));
    print("SUCCESS: Client 1 received ICE: ${receivedIce['candidate']}");
    expect(receivedIce['sdpMid'], equals('0'));

    print("ALL THREE SIGNALING STEPS (OFFER, ANSWER, ICE) VERIFIED PERFECTLY!");

    ch1.unsubscribe();
    ch2.unsubscribe();
  });
}
